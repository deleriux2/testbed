#include "common.h"
#include "ndmp.h"
#include "ndmp_common.h"

#include <sys/utsname.h>

static int _ndmp_read(void *data, void *buf, int len);
static int _ndmp_write(void *data, void *buf, int len);

ndmp_session *ndmp_init_session(int fd)
{
	ndmp_session *sess = NULL;
	ON_ERR("Cannot allocate memory", sess = malloc(sizeof(*sess)));
	memset(sess, 0, sizeof(*sess));
	struct utsname unm;
	memset(&unm, 0, sizeof(unm));

	sess->protocol = NDMP_VER;
	sess->poll = -1;
	sess->signalfd = -1;
	sess->pipe = -1;
	sess->fd = fd;
	sess->backup_fd = -1;
	sess->seqno = 0;
	sess->peer_seqno = 0;
	sess->connected = false;
	sess->authenticated = false;

	sess->state.bytes_processed = 0;
	sess->state.bytes_remaining = 0;
	sess->state.time_remaining = 0;
	sess->state.read_offset = 0;
	sess->state.read_length = 0;
	sess->state.data_state = NDMP_DATA_STATE_IDLE;
	sess->state.operation = NDMP_DATA_OP_NOACTION;
	sess->state.halt_reason = NDMP_DATA_HALT_NA;
	sess->state.peer_env = NULL;
	sess->state.peer_env_len = 0;
	memset(&sess->state.addr, 0, sizeof(sess->state.addr));

	strncpy(sess->username, "matthew", 256);
	strncpy(sess->password, "abc123", 256);
	snprintf(sess->vendor_name, 256, "%s %s", unm.sysname, unm.release);
	strncpy(sess->product_name, "NDMP Test implementation", 256);
	strncpy(sess->revision_number, VERSION, 256);
	memset(sess->challenge, 0, sizeof(sess->challenge));

	xdrrec_create(&sess->xdrs, 0, 0, (void *)sess, _ndmp_read, _ndmp_write);
	xdrrec_skiprecord(&sess->xdrs);
	return sess;
}

void ndmp_free_session(ndmp_session *sess) {
	if (!sess) return;

	if (sess->state.peer_env != NULL)
		free(sess->state.peer_env);
	xdr_destroy(&sess->xdrs);
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

	rc = recv(sess->fd, buf, len, 0);
	if (rc < 0) {
		fprintf(stderr, "Cannot recv data: %s\n", strerror(errno));
	}
	else if (rc == 0) {
		fprintf(stderr, "Cannot recv data: No data received\n");
		rc = -1;
	}
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

