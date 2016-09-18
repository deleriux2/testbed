#include "common.h"
#include "ndmp.h"
#include "ndmp_common.h"


static int _ndmp_read(void *data, void *buf, int len);
static int _ndmp_write(void *data, void *buf, int len);

ndmp_session *ndmp_init_session()
{
	ndmp_session *sess = NULL;
	ON_ERR("Cannot allocate memory", sess = malloc(sizeof(*sess)));

	sess->protocol = 4;
	sess->fd = -1;
	sess->seqno = 0;
	sess->connected = false;
	sess->authenticated = false;
	sess->fslist_len = 0;

	memset(sess->peername, 0, sizeof(sess->peername));
	memset(sess->peerport, 0, sizeof(sess->peerport));
	memset(sess->username, 0, sizeof(sess->username));
	memset(sess->password, 0, sizeof(sess->password));
	memset(sess->challenge, 0, sizeof(sess->challenge));
	memset(sess->vendor_name, 0, sizeof(sess->vendor_name));
	memset(sess->product_name, 0, sizeof(sess->product_name));
	memset(sess->revision_number, 0, sizeof(sess->revision_number));
	sess->fslist = NULL;

	xdrrec_create(&sess->xdrs, 0, 0, (void *)sess, _ndmp_read, _ndmp_write);
	xdrrec_skiprecord(&sess->xdrs);
	return sess;
}

void ndmp_free_session(ndmp_session *sess) {
	if (!sess) return;

	ndmp_disconnect(sess);
	free(sess);
}

static int _ndmp_read(
		void *data,
		void *buf,
		int len)
{
	ndmp_session *sess = (ndmp_session *)data;
	int rc;
	assert(sess);
	assert(buf);
	assert(len >= 0);

	ON_ERR("Cannot recv data", rc = recv(sess->fd, buf, len, 0));
	return rc;
}

static int _ndmp_write(
	void *data,
	void *buf,
	int len)
{
	ndmp_session *sess = (ndmp_session *)data;
	int rc;
	assert(sess);
	assert(buf);
	assert(len >= 0);

	ON_ERR("Unable to send data", rc = send(sess->fd, buf, len, MSG_NOSIGNAL));
	return rc;
}

