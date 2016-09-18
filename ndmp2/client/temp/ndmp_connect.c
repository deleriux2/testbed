#include "common.h"
#include "ndmp.h"
#include "ndmp_common.h"

#include <sys/socket.h>
#include <netdb.h>
#include <openssl/md5.h>

extern ndmp_session *ndmp_init_session();
extern int ndmp_header_recv(ndmp_session *sess, ndmp_header *hdr);
int ndmp_header_send(ndmp_session *sess, ndmp_message code);

bool ndmp_recv_notify_connection_status(ndmp_session *sess, ndmp_header *hdr);
bool ndmp_send_connect_open_request(ndmp_session *sess);
bool ndmp_recv_connect_open_reply(ndmp_session *sess);
bool ndmp_send_connect_client_auth_request(ndmp_session *sess);
bool ndmp_recv_connect_client_auth_reply(ndmp_session *sess);

static bool ndmp_get_notify_connection_status(ndmp_session *sess);

static int create_md5_challenge_response(
      char *password,
      char *challenge,
      char *response)
{
/* This is computed as follows
 * Take the length of password.
 * Padding = 64 - (2 * length)
 * Place in buffer as password + padding + challenge + password
 * Perform hash
 * Return response */
   char buf[128];
   char *p = buf;
   int plen = strlen(password);

   if (plen > 32) {
      plen = 32;
   }
   int padlen = 64 - (2 * plen);
   memcpy(p, password, plen);
   p += plen;
   memset(p, 0, padlen);
   p += padlen;
   memcpy(p, challenge, 64);
   p += 64;
   memcpy(p, password, plen);

	MD5(buf, 128, response);
   return 1;
}

static int tcp_connect(
		char *host,
		char *port)
{
	int fd = -1;
	int rc;
	struct addrinfo *ai = NULL;

	if ((rc = getaddrinfo(host, port, NULL, &ai) != 0)) {
		fprintf(stderr, "Unable to resolve address: %s\n", gai_strerror(rc));
		goto fail;
	}

	ON_ERR(
		"Cannot create socket",
		fd = socket(AF_INET, SOCK_STREAM, 0)
	);
	ON_ERR(
		"Cannot connect to host",
		connect(fd, ai->ai_addr, ai->ai_addrlen)
	);

	return fd;

fail:
	return -1;
}

void ndmp_disconnect(
		ndmp_session *sess)
{
	if (!sess) return;
	if (sess->connected) {
		ndmp_header_send(sess, NDMP_CONNECT_CLOSE);
	   xdrrec_endofrecord(&sess->xdrs, 1);
	}
	shutdown(sess->fd, SHUT_RDWR);
	close(sess->fd);
	sess->fd = -1;
	sess->connected = 0;
	sess->authenticated = 0;
}

/* If username is null, do auth none type */
ndmp_session * ndmp_connect(
		char *host,
		char *port,
		char *username,
		char *password)
{
	assert(host);
	assert(port);

	ndmp_session *sess = ndmp_init_session();

	if (username) {
		strncpy(sess->username, username, 256);
		strncpy(sess->password, password, 256);
	}
	strncpy(sess->peername, host, 256);
	strncpy(sess->peerport, port, 64);

	sess->fd = tcp_connect(host, port);

	/* check the server is accepting connections */
	if (!ndmp_get_notify_connection_status(sess)) 
		goto fail;

	/* Send our 'demand' for the protocol we want. */
	if (!ndmp_send_connect_open_request(sess)) 
		goto fail;
	if (!ndmp_recv_connect_open_reply(sess)) 
		goto fail;

	sess->connected = true;

	/* Check the auth types we want are supported */
	if (!ndmp_send_config_get_server_info_request(sess)) 
		goto fail;

	if (!ndmp_recv_config_get_server_info_reply(sess))
		goto fail;

	/* Get a challenge blob */
	if (!ndmp_send_config_get_auth_attr_request(sess))
		goto fail;

	if (!ndmp_recv_config_get_auth_attr_reply(sess))
		goto fail;

	/* Authenticate */
	if (!ndmp_send_connect_client_auth_request(sess))
		goto fail;

	if (!ndmp_recv_connect_client_auth_reply(sess))
		goto fail;

	sess->authenticated = true;

	return sess;

fail:
	ndmp_free_session(sess);
	return NULL;
}

bool ndmp_get_notify_connection_status(
		ndmp_session *sess)
{
	ndmp_header hdr;
	if (ndmp_header_recv(sess, &hdr) != 1) {
		fprintf(stderr, "Error in receive request: %s\n", ndmp_print_error(hdr.error_code));
		/* No disconnect needed */
		return false;
	}

	if (!ndmp_recv_notify_connection_status(sess, &hdr))
		return false;

	return true;
}

bool ndmp_recv_notify_connection_status(
		ndmp_session *sess,
		ndmp_header *hdr)
{
	ndmp_notify_connection_status_post *cstatus = NULL;
	ON_ERR("Memory allocation error",
		cstatus = malloc(sizeof(*cstatus))
	);

	if (hdr->message_type != NDMP_MESSAGE_REQUEST) {
		fprintf(stderr, "Expected a message request but got something else\n");
	}
	if (hdr->message_code != NDMP_NOTIFY_CONNECTION_STATUS) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_notify_connection_status_post(&sess->xdrs, cstatus)) {
		goto fail;
	}

	/* Check if we are open for business */
	if (cstatus->reason == NDMP_REFUSED) {
		fprintf(stderr, "The server is not accepting connections: %s\n", cstatus->text_reason);
		goto fail;
	}
	else if (cstatus->reason == NDMP_REFUSED) {
		fprintf(stderr, "The server is shutting down: %s\n", cstatus->text_reason); 
	}

	if (cstatus->protocol_version != NDMP_VER) {
		fprintf(stderr, "This server suggests a version we do not support: version %d\n", cstatus->protocol_version);
		goto fail;
	}

	free(cstatus);
	xdrrec_skiprecord(&sess->xdrs);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	free(cstatus);
	return false;
}

bool ndmp_send_connect_open_request(
		ndmp_session *sess)
{
	ndmp_connect_open_request open;

	if (!ndmp_header_send(sess, NDMP_CONNECT_OPEN)) {
		return 0;
	}

	open.protocol_version = NDMP_VER;
	sess->xdrs.x_op = XDR_ENCODE;
	if (!xdr_ndmp_connect_open_request(&sess->xdrs, &open)) {
		return 0;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		return 0;
	}
	return 1;
}

bool ndmp_recv_connect_open_reply(
		ndmp_session *sess)
{
	ndmp_connect_open_reply oreply;
	ndmp_header hdr;
	int rc;

	if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
		fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
		return false;
	}

	if (hdr.message_type != NDMP_MESSAGE_REPLY) {
		fprintf(stderr, "Expected a message request but got something else\n");
	}
	if (hdr.message_code != NDMP_CONNECT_OPEN) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_connect_open_reply(&sess->xdrs, &oreply)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	if (oreply.error != NDMP_NO_ERR) {
		fprintf(stderr, "Attempting to a protocol has failed: %s\n", ndmp_print_error(oreply.error));
		goto fail;
	}

	xdrrec_skiprecord(&sess->xdrs);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	return false;
}

bool ndmp_send_connect_client_auth_request(
		ndmp_session *sess)
{
	char md5resp[16];
	ndmp_connect_client_auth_request auth;
	auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id = NULL;

   if (!ndmp_header_send(sess, NDMP_CONNECT_CLIENT_AUTH)) {
      return 0;
   }

	if (sess->username[0] != 0) {
		auth.auth_data.auth_type = NDMP_AUTH_MD5;
		if (!create_md5_challenge_response(sess->password, sess->challenge, md5resp)) {
			fprintf(stderr, "Could not generate an md5 challenge\n");
			goto fail;
		}
		auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id = strdup(sess->username);
		strncpy(auth.auth_data.ndmp_auth_data_u.auth_md5.auth_digest, md5resp, 16);
	}
	else {
		auth.auth_data.auth_type = NDMP_AUTH_NONE;
	}

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_connect_client_auth_request(&sess->xdrs, &auth)) {
		goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }


	free(auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id);
   return true;

fail:
	if (sess->username[0] != 0) {
		if (auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id)
			free(auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id);
	}
	return false;
}

bool ndmp_recv_connect_client_auth_reply(
		ndmp_session *sess)
{
	ndmp_connect_client_auth_reply areply;

   ndmp_header hdr;
   int rc;

   if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
      fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
      return false;
   }

   if (hdr.message_type != NDMP_MESSAGE_REPLY) {
      fprintf(stderr, "Expected a message request but got something else\n");
   }
   if (hdr.message_code != NDMP_CONNECT_CLIENT_AUTH) {
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_connect_client_auth_reply(&sess->xdrs, &areply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

   if (areply.error != NDMP_NO_ERR) {
      fprintf(stderr, "Authentication failure: %s\n", ndmp_print_error(areply.error));
      goto fail;
   }

   xdrrec_skiprecord(&sess->xdrs);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   return false;
}
