#include "common.h"
#include "ndmp_common.h"

#include <sys/socket.h>
#include <netdb.h>
#include <openssl/md5.h>

extern int err_major;
extern int err_minor;
extern int ndmp_header_recv(ndmp_session *sess, ndmp_header *hdr);
int ndmp_header_send(ndmp_session *sess, ndmp_message code);

bool ndmp_recv_notify_connection_status(ndmp_session *sess);
static bool ndmp_send_connect_open_request(ndmp_session *sess);
static bool ndmp_recv_connect_open_reply(ndmp_session *sess);
static bool ndmp_send_connect_client_auth_request(ndmp_session *sess, char challenge[64]);
static bool ndmp_recv_connect_client_auth_reply(ndmp_session *sess);

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

   /* To inform caller that this was a lookup issue */
   if ((rc = getaddrinfo(host, port, NULL, &ai) != 0)) {
      return -rc - 100;
   }

   if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
     goto fail;

   if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0)
     goto fail;

   return fd;

fail:
   return -1;
}

void ndmp_disconnect(
      ndmp_session *sess)
{
   if (!sess) return;
   if (sess->fd > -1) {
      ndmp_header_send(sess, NDMP_CONNECT_CLOSE);
      xdrrec_endofrecord(&sess->xdrs, 1);
      shutdown(sess->fd, SHUT_RDWR);
      close(sess->fd);
      sess->fd = -1;
   }
}

/* If username is null, do auth none type */
bool ndmp_connect(
      ndmp_session *sess,
      char *host,
      char *port,
      char *username,
      char *password)
{
   assert(sess);
   assert(host);
   assert(port);

   char challenge[64]; 
   ndmp_server_info info;
   memset(&info, 0, sizeof(info));
   memset(challenge, 0, 64);

   if (username) {
      strncpy(sess->username, username, 64);
      strncpy(sess->password, password, 64);
   }
   strncpy(sess->peerhost, host, 256);
   strncpy(sess->peerport, port, 32);

   /* TCP connect */
   sess->fd = tcp_connect(host, port);
   if (sess->fd == -1) {
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
   }
   else if (sess->fd < -100) {
     SET_ERR(sess, MAJ_LOOKUP_ERROR, (-sess->fd)-100, fail);
   }

   /* check the server is accepting connections */
   if (!ndmp_get_notify_connection_status(sess))
      goto fail;

   /* Send our 'demand' for the protocol we want. */
   if (!ndmp_send_connect_open_request(sess))
      goto fail;
   if( !ndmp_recv_connect_open_reply(sess))
      goto fail;

   /* Check the auth types we want are supported */
   if (!ndmp_get_server_info(sess, &info))
      goto fail;

   /* Get challenge blob */
   if (!ndmp_get_challenge(sess, challenge))
      goto fail;

   /* Authenticate */
   if (!ndmp_send_connect_client_auth_request(sess, challenge))
      goto fail;
   if (!ndmp_recv_connect_client_auth_reply(sess))
      goto fail;

   return true;
fail:
   ndmp_disconnect(sess);
   ndmp_free_session(sess);
   return false;
}

bool ndmp_get_notify_connection_status(
      ndmp_session *sess)
{
   ndmp_header hdr;
   sess->error = hdr.error_code;
   if (ndmp_header_recv(sess, &hdr) != 1)
      goto fail;

   if (hdr.message_type != NDMP_MESSAGE_REQUEST) {
      SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_NOT_REQUEST, fail);
   }

   if (hdr.message_code != NDMP_NOTIFY_CONNECTION_STATUS) {
      sess->err_text = strdup("expected notify connection status");
      SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_BAD_MESSAGECODE, fail);
   }

   if (!ndmp_recv_notify_connection_status(sess))
     goto fail;

   return true;

fail:
   return false;
}


bool ndmp_recv_notify_connection_status(
      ndmp_session *sess)
{
   assert(sess);

   ndmp_notify_connection_status_post cstatus;
   memset(&cstatus, 0, sizeof(cstatus));

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_notify_connection_status_post(&sess->xdrs, &cstatus))
     SET_ERR(sess, MAJ_CONNECT_ERROR, STATUS_POST_DECODE, fail);

   /* Check if we are open for business */
   if (cstatus.reason != NDMP_CONNECTED) { 
      sess->err_text = strdup(cstatus.text_reason);
      SET_ERR(sess, MAJ_CONNECT_ERROR, cstatus.reason, fail);
   }

   if (cstatus.protocol_version != NDMP_VER) {
      sess->err_text = calloc(16, 1);
      snprintf(sess->err_text, 16, "%d", cstatus.protocol_version);
      SET_ERR(sess, MAJ_CONNECT_ERROR, INVALID_PROTOCOL_VERSION, fail);
   }

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_stop_reply, &cstatus);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_stop_reply, &cstatus);
   return false;
}


static bool ndmp_send_connect_open_request(
      ndmp_session *sess)
{
   assert(sess);
   ndmp_connect_open_request open;

   if (!ndmp_header_send(sess, NDMP_CONNECT_OPEN))
      goto fail;

   open.protocol_version = NDMP_VER;
   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_connect_open_request(&sess->xdrs, &open))
      SET_ERR(sess, MAJ_CONNECT_ERROR, OPEN_ENCODE, fail);

   if (!xdrrec_endofrecord(&sess->xdrs, 1))
      SET_ERR(sess, MAJ_XDR_ERROR, SEND_ERROR, fail);

   xdr_free((xdrproc_t)xdr_ndmp_connect_open_request, &open);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_connect_open_request, &open);
   return false;
}

static bool ndmp_recv_connect_open_reply(
      ndmp_session *sess)
{
   assert(sess);

   ndmp_connect_open_reply reply;
   memset(&reply, 0, sizeof(reply));
   REPLY_HEADER_CHECKS(NDMP_CONNECT_OPEN);

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_connect_open_reply(&sess->xdrs, &reply))
      SET_ERR(sess, MAJ_CONNECT_ERROR, OPEN_DECODE, fail);

   /* The error status of the response packet must be checked here too */
   sess->error = reply.error;
   if (reply.error != NDMP_NO_ERR)
      SET_ERR(sess, MAJ_HEADER_ERROR, reply.error, fail);

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_connect_open_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_connect_open_reply, &reply);
   return false;
}


static bool ndmp_send_connect_client_auth_request(
      ndmp_session *sess,
      char challenge[64])
{
   assert(sess);
   assert(challenge);

   char md5resp[16]; memset(md5resp, 0, sizeof(md5resp));
   ndmp_connect_client_auth_request auth; memset(&auth, 0, sizeof(auth));

   auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id = NULL;

   if (!ndmp_header_send(sess, NDMP_CONNECT_CLIENT_AUTH))
      goto fail;

   if (sess->username[0] != 0) {
      auth.auth_data.auth_type = NDMP_AUTH_MD5;
      if (!create_md5_challenge_response(sess->password, challenge, md5resp))
         SET_ERR(sess, MAJ_CONNECT_ERROR, HASH_FAIL, fail);

      auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id = strdup(sess->username);
      strncpy(auth.auth_data.ndmp_auth_data_u.auth_md5.auth_digest, md5resp, 16);
   }
   else {
      auth.auth_data.auth_type = NDMP_AUTH_NONE;
   }

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_connect_client_auth_request(&sess->xdrs, &auth))
      SET_ERR(sess, MAJ_CONNECT_ERROR, AUTH_ENCODE, fail);
   if (!xdrrec_endofrecord(&sess->xdrs, 1))
      SET_ERR(sess, MAJ_XDR_ERROR, SEND_ERROR, fail);

   xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_request, &auth);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_request, &auth);
   return false;
}


static bool ndmp_recv_connect_client_auth_reply(
      ndmp_session *sess)
{
   ndmp_connect_client_auth_reply reply;

   REPLY_HEADER_CHECKS(NDMP_CONNECT_CLIENT_AUTH);

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_connect_client_auth_reply(&sess->xdrs, &reply))
      SET_ERR(sess, MAJ_CONNECT_ERROR, AUTH_DECODE, fail);

   if (reply.error != NDMP_NO_ERR)
      SET_ERR(sess, MAJ_HEADER_ERROR, reply.error, fail);

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_reply, &reply);
   xdrrec_skiprecord(&sess->xdrs);
   return false;
}
