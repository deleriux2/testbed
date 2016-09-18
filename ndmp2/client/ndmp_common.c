#include "common.h"
#include "ndmp.h"
#include "ndmp_common.h"

#include <sys/mman.h>

static int _ndmp_read(void *data, void *buf, int len);
static int _ndmp_write(void *data, void *buf, int len);

ndmp_databackup *ndmp_init_databackup()
{
	/* We explicitly make this structure here in an mmap, as we want to share
	 * the memory with a child process later on */
	ndmp_databackup *backup;
	backup = mmap(NULL, sizeof(*backup), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
	if (backup == NULL) {
		fprintf(stderr, "Cannot allocate memory for backup: %s\n", strerror(errno));
		return NULL;
	}
	memset(backup, 0, sizeof(*backup));

	return backup;
}

void ndmp_destroy_databackup(
	ndmp_databackup *backup)
{
	munmap(backup, sizeof(*backup));
}

ndmp_session *ndmp_init_session()
{
	ndmp_session *sess = NULL;
	ON_ERR("Cannot allocate memory", sess = malloc(sizeof(*sess)));

	sess->protocol = 4;
	sess->fd = -1;
	sess->seqno = 0;
	sess->peer_seqno = 0;
	sess->connected = false;
	sess->authenticated = false;
	sess->fslist_len = 0;
	sess->backup = ndmp_init_databackup();
	sess->backup_pid = -1;
	sess->peer_env_len = 0;

	memset(sess->peername, 0, sizeof(sess->peername));
	memset(sess->peerport, 0, sizeof(sess->peerport));
	memset(sess->username, 0, sizeof(sess->username));
	memset(sess->password, 0, sizeof(sess->password));
	memset(sess->challenge, 0, sizeof(sess->challenge));
	memset(sess->vendor_name, 0, sizeof(sess->vendor_name));
	memset(sess->product_name, 0, sizeof(sess->product_name));
	memset(sess->revision_number, 0, sizeof(sess->revision_number));
	sess->fslist = NULL;
	sess->bklist = NULL;
	sess->peer_env = NULL;

	xdrrec_create(&sess->xdrs, 0, 0, (void *)sess, _ndmp_read, _ndmp_write);
	xdrrec_skiprecord(&sess->xdrs);
	return sess;
}

void ndmp_free_session(ndmp_session *sess) {
	if (!sess) return;

	int i,j;
	ndmp_disconnect(sess);
	ndmp_destroy_databackup(sess->backup);
	for (i=0; i < sess->fslist_len; i++) {
		free(sess->fslist[i].metadata);
	}

	for (i=0; i < sess->bklist_len; i++) {
      free(sess->bklist[i].metadata);
	}
	free(sess->peer_env);
	free(sess->bklist);
	free(sess->fslist);
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
		return rc;
   }
   
else if (rc == 0) {
		errno = ENODATA;
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

