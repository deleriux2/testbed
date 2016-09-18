#include "common.h"
#include "ndmp_common.h"

#include <sys/epoll.h>

#define MAX_FDS 4096
struct ndmp_callback *cblist[MAX_FDS];

int num_fds;
static bool ndmp_dma_dispatcher_cb(ndmp_session *sess);


bool ndmp_dispatcher_add_fd(
		ndmp_session *sess, 
		int fd,
		enum ndmp_event event,
		bool (*callback)(ndmp_session *))
{
	int i;
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
   struct ndmp_callback *cb = calloc(sizeof(*cb), 1);
   if (!cb) {
      fprintf(stderr, "Cannot allocate memory for callback: %s\n", strerror(errno));
      return false;
   }

   cb->sess = sess;
	cb->fd = fd;
   cb->callback = callback;

	for (i=0; i < MAX_FDS; i++) {
		if (cblist[i] == NULL) {
			cblist[i] = cb;
			break;
		}
	}
	if (i == MAX_FDS) {
		fprintf(stderr, "Cannot add to dispatcher: Ran ouf of FDs to use!\n");
		free(cb);
		return false;
	}

	ev.events = event;
	ev.data.ptr = cb;

	if (epoll_ctl(sess->poll, EPOLL_CTL_ADD, fd, &ev) < 0) {
		fprintf(stderr, "Unable to add fd to dispatcher: %s\n", strerror(errno));
		free(cb);
		return false;
	}
	num_fds++;
	return true;
}

bool ndmp_dispatcher_del_fd(
      ndmp_session *sess,
      int fd)
{
	int i;
	if (fd < 0) return false;

	for (i=0; i < MAX_FDS; i++) {
		if (cblist[i] != NULL && cblist[i]->fd == fd) {
			free(cblist[i]);
			cblist[i] = NULL;
			break;
		}
	}
	if (i == MAX_FDS) {
		/* Was removed in a previous iteration of the dispatcher */
		return false;
	}

   if (epoll_ctl(sess->poll, EPOLL_CTL_DEL, fd, NULL) < 0) {
		if (errno == EBADF) return false;

      fprintf(stderr, "Unable to delete fd %d from dispatcher: %s\n", fd, strerror(errno));
      return false;
   }
	else {
	}
	num_fds--;
   return true;
}

bool ndmp_dispatcher_mod_fd(
      ndmp_session *sess,
      int fd,
      enum ndmp_event event,
		bool (*callback)(ndmp_session *sess))
{
	int i;
	struct ndmp_callback *cb = NULL;
   struct epoll_event ev;
   memset(&ev, 0, sizeof(ev));

	for (i=0; i < MAX_FDS; i++) {
		if (cblist[i] != NULL && cblist[i]->fd == fd) {
			cb = cblist[i];
			break;
		}
	}
	if (i == MAX_FDS) {
		fprintf(stderr, "Could not find callback in cblist to modify!\n");
		return false;
	}

	cb->sess = sess;
	cb->fd = fd;
	cb->callback = callback;

   ev.events = event;
	ev.data.ptr = cb;	

   if (epoll_ctl(sess->poll, EPOLL_CTL_MOD, fd, &ev) < 0) {
      fprintf(stderr, "Unable to modify fd in dispatcher: %s\n", strerror(errno));
		cblist[i] = NULL;
		free(cb);
      return false;
   }
   return true;
}

bool ndmp_dma_dispatcher(
		ndmp_session *sess)
{
	num_fds = 0;
	int oldfds = 0;
	bool worked;
	int rc = 0;
	int i = 0;
	struct epoll_event *evs = NULL;
	struct ndmp_callback *cb = NULL;
	memset(cblist, 0, sizeof(*cblist) * MAX_FDS);

	sess->poll = epoll_create1(EPOLL_CLOEXEC);
	if (sess->poll < 0) {
		fprintf(stderr, "Dispatcher cannot create epoll: %s\n", strerror(errno));
		return false;
	}

	/* For now, the only thing we care to add is the client fd we poll */
	ndmp_dispatcher_add_fd(sess, sess->fd, NDMP_IN, ndmp_dma_dispatcher_cb);

	while (num_fds > 0 && sess->poll > -1) {
		if (oldfds != num_fds || evs == NULL) {
			evs = realloc(evs, sizeof(*evs)*num_fds);
			if (!evs) {
				fprintf(stderr, "Memory allocation error when event storage was attempted: %s\n", strerror(errno));
				return false;
			}
		}
		rc = epoll_wait(sess->poll, evs, num_fds, -1);
		if (rc < 0 && errno == EINTR) {
			continue;
		}
		else if (rc < 0) {
			fprintf(stderr, "Epoll failed: %s\n", strerror(errno));
			return false;
		}
		for (i=0; i < rc; i++) {
			cb = evs[i].data.ptr;
			worked = cb->callback(cb->sess);
			if (!worked) {
				ndmp_dispatcher_del_fd(cb->sess, cb->fd);
			}
		}
	}
	free(evs);
	return true;
}


static bool ndmp_dma_dispatcher_cb(
		ndmp_session *sess)
{
	int rc;
	bool failed = false;
	ndmp_header hdr;
	if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
		if (rc == -1) {
			fprintf(stderr, "Error in receive request: HDR Decode error\n");
		}
		else {
			fprintf(stderr, "Error in receive request: %s\n", ndmp_print_error(hdr.error_code));
		}
		goto fail;
	}

	if (hdr.message_type == NDMP_MESSAGE_REPLY) {
		if (sess->seqno != hdr.reply_sequence) {
			fprintf(stderr, "Unexpected sequence number\n");
			goto fail;
		}
	}
	else if (hdr.message_type == NDMP_MESSAGE_REQUEST) {
		if (sess->peer_seqno != hdr.sequence) {
			fprintf(stderr, "Unexpected sequence number\n");
			goto fail;
		}
	}

	switch(hdr.message_code) {

	case NDMP_LOG_MESSAGE:
		if (!ndmp_recv_log_message_post(sess))
			failed = true;
		break;

	case NDMP_NOTIFY_DATA_HALTED:
		ndmp_recv_notify_data_halted_post(sess);
		goto fail;
		break;

	default:
		fprintf(stderr, "Unknown message code: 0x%x\n", hdr.message_code);
		xdrrec_skiprecord(&sess->xdrs);
		break;
	}
	if (failed) {
		fprintf(stderr, "Internal error\n", hdr.message_code);
		xdrrec_skiprecord(&sess->xdrs);
		goto fail;
	}

	return true;
fail:
	return false;
}

