#include "common.h"
#include "ndmp_common.h"

#include <signal.h>
#include <openssl/md5.h>

extern ndmp_send_header(ndmp_session *sess, ndmp_message msg);
extern ndmp_send_header_reply(ndmp_session *sess, ndmp_message msg);

static int create_md5_challenge_response(char *password, char *challenge, char *response);

static bool ndmp_send_connect_open_reply(ndmp_session *sess, ndmp_error error);
static bool ndmp_send_connect_client_auth_reply(ndmp_session *sess, ndmp_error error);

static int create_md5_challenge_response(
		char *password,
		char *challenge,
		char *response)
{
/* This is computed as follows
 *  * Take the length of password.
 *	* Padding = 64 - (2 * length)
 *	 * Place in buffer as password + padding + challenge + password
 *	  * Perform hash
 *		* Return response */
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

void ndmp_disconnect(
		ndmp_session *sess)
{
	if (!sess)
		return;

	if (sess->connected) {
		ndmp_send_notify_connection_status(sess, NDMP_SHUTDOWN, "Error in communication. Aborting connection");
	}

fin:
	shutdown(sess->fd, SHUT_RDWR);
	if (sess->pipe >= 0) {
		ndmp_dispatcher_del_fd(sess, sess->pipe);
		close(sess->pipe);
	}
	if (sess->epipe >= 0) {
		ndmp_dispatcher_del_fd(sess, sess->epipe);
		close(sess->epipe);
	}
	if (sess->signalfd >= 0) {
		ndmp_dispatcher_del_fd(sess, sess->signalfd);
		close(sess->signalfd);
	}
	if (sess->backup_fd >= 0) {
		close(sess->backup_fd);
	}
	close(sess->fd);
	close(sess->poll);
	sess->connected = 0;
	sess->authenticated = 0;
	sess->fd = -1;
	sess->signalfd = -1;
	sess->pipe = -1;
	sess->epipe = -1;
	sess->poll = -1;
	sess->backup_fd = -1;
	sess->state.time_remaining = 0;
	sess->state.bytes_remaining = 0;
	sess->state.bytes_processed = 0;
	sess->state.data_state = NDMP_DATA_STATE_IDLE;
	sess->state.operation = NDMP_DATA_OP_NOACTION;
	sess->state.halt_reason = NDMP_DATA_HALT_NA;
	if (sess->dumper_pid > 0) {
		kill(sess->dumper_pid, SIGTERM);
		sess->dumper_pid = -1;
	}
	return;
}


bool ndmp_send_notify_connection_status(
		ndmp_session *sess,
		ndmp_connection_status_reason status,
		char *reason)
{
	ndmp_notify_connection_status_post post;
	memset(&post, 0, sizeof(post));

	if(!ndmp_header_send(sess, NDMP_NOTIFY_CONNECTION_STATUS))
		goto fail;

	sess->xdrs.x_op = XDR_ENCODE;
	post.reason = status;
	post.protocol_version = NDMP_VER;
	post.text_reason = strdup(reason);
	if (!xdr_ndmp_notify_connection_status_post(&sess->xdrs, &post)) {
		goto fail;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		goto fail;
	}

	xdr_free((xdrproc_t)xdr_ndmp_notify_connection_status_post, &post);
	return true;

fail:
	xdr_free((xdrproc_t)xdr_ndmp_notify_connection_status_post, &post);
	return false;
}


bool ndmp_recv_connect_open_request(
	ndmp_session *sess)
{
	ndmp_connect_open_request open;
	memset(&open, 0, sizeof(open));

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_connect_open_request(&sess->xdrs, &open)) {
		goto fail;
	}
	xdrrec_skiprecord(&sess->xdrs);

	if (sess->connected) {
		if (!ndmp_send_connect_open_reply(sess, NDMP_ILLEGAL_STATE_ERR))
			goto fail;
	}

	if (open.protocol_version != NDMP_VER) {
		if (!ndmp_send_connect_open_reply(sess, NDMP_ILLEGAL_ARGS_ERR))
			goto fail;
	}

	if (!ndmp_send_connect_open_reply(sess, NDMP_NO_ERR))
		goto fail;

	xdr_free((xdrproc_t)xdr_ndmp_connect_open_request, &open);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_connect_open_request, &open);
	return false;
}


static bool ndmp_send_connect_open_reply(
		ndmp_session *sess,
		ndmp_error error)
{
	ndmp_connect_open_reply reply;
	memset(&reply, 0, sizeof(reply));

	if(!ndmp_header_send_reply(sess, NDMP_CONNECT_OPEN))
		goto fail;

	sess->xdrs.x_op = XDR_ENCODE;
	reply.error = error;
	if (!xdr_ndmp_connect_open_reply(&sess->xdrs, &reply)) {
		goto fail;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		goto fail;
	}

	xdr_free((xdrproc_t)xdr_ndmp_connect_open_reply, &reply);
	sess->connected = true;
	return true;

fail:
	xdr_free((xdrproc_t)xdr_ndmp_connect_open_reply, &reply);
	return false;
}


bool ndmp_recv_connect_client_auth_request(ndmp_session *sess)
{
	ndmp_connect_client_auth_request auth;
	memset(&auth, 0, sizeof(auth));
	char *user;
	char *dgst;
	char our_digest[16];

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_connect_client_auth_request(&sess->xdrs, &auth)) {
		goto fail;
	}

#ifdef SUPPORT_AUTH_NONE
	if (auth.auth_type == NDMP_AUTH_NONE) {
		if (!ndmp_send_connect_client_auth_reply(sess, NDMP_NO_ERR))
			goto fail;
	}
	else 
#endif

	if (auth.auth_data.auth_type == NDMP_AUTH_MD5) {
		dgst = auth.auth_data.ndmp_auth_data_u.auth_md5.auth_digest;
		user = auth.auth_data.ndmp_auth_data_u.auth_md5.auth_id;

		if (strncmp(user, sess->username, 256) != 0)
			if (!ndmp_send_connect_client_auth_reply(sess, NDMP_NOT_AUTHORIZED_ERR))
				goto fail;

		if (!create_md5_challenge_response(sess->password, sess->challenge, our_digest)) {
			fprintf(stderr, "Unable to create md5 challenge response\n");
			goto fail;
		}

		if (strncmp(our_digest, dgst, 16) == 0) {
			if (!ndmp_send_connect_client_auth_reply(sess, NDMP_NO_ERR))
				goto fail;
		}
		else {
			if (!ndmp_send_connect_client_auth_reply(sess, NDMP_NOT_AUTHORIZED_ERR))
				goto fail;
		}
	}
	else {
		if (!ndmp_send_connect_client_auth_reply(sess, NDMP_ILLEGAL_ARGS_ERR))
			goto fail;
	}

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_request, &auth);
	sess->authenticated = true;
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_request, &auth);
	return false;	
}


static bool ndmp_send_connect_client_auth_reply(
		ndmp_session *sess,
		ndmp_error error)
{
	ndmp_connect_client_auth_reply reply; 
	memset(&reply, 0, sizeof(reply));

	if(!ndmp_header_send_reply(sess, NDMP_CONNECT_CLIENT_AUTH))
		goto fail;

	sess->xdrs.x_op = XDR_ENCODE;
	reply.error = error;
	if (!xdr_ndmp_connect_client_auth_reply(&sess->xdrs, &reply)) {
		goto fail;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		goto fail;
	}

	xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_reply, &reply);
	return true;

fail:
	xdr_free((xdrproc_t)xdr_ndmp_connect_client_auth_reply, &reply);
	return false;	
}
