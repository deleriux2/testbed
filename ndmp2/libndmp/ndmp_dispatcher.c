#include "common.h"
#include "ndmp_common.h"

#include <sys/epoll.h>

#define MAX_FDS 4096
#define DISPATCHER_MAX_FDS 0
#define DISPATCHER_NO_CALLBACK 1

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
   if (!cb)
     SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);

   cb->sess = sess;
   cb->fd = fd;
   cb->callback = callback;

   for (i=0; i < MAX_FDS; i++) {
      if (cblist[i] == NULL) {
         cblist[i] = cb;
         break;
      }
   }
   if (i == MAX_FDS)
      SET_ERR(sess, MAJ_APPLICATION_ERROR, DISPATCHER_MAX_FDS, fail);

   ev.events = event;
   ev.data.ptr = cb;

   if (epoll_ctl(sess->poll, EPOLL_CTL_ADD, fd, &ev) < 0)
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
   sess->numfds++;
   return true;

fail:
  if (cb) free(cb);
  return false;
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
   if (i == MAX_FDS)
      /* Was removed in a previous iteration of the dispatcher */
      SET_ERR(sess, MAJ_APPLICATION_ERROR, DISPATCHER_NO_CALLBACK, fail);

   if (epoll_ctl(sess->poll, EPOLL_CTL_DEL, fd, NULL) < 0)
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
   sess->numfds--;
   return true;

fail:
   return false;
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
   if (i == MAX_FDS)
      SET_ERR(sess, MAJ_APPLICATION_ERROR, DISPATCHER_NO_CALLBACK, fail);

   cb->sess = sess;
   cb->fd = fd;
   cb->callback = callback;

   ev.events = event;
   ev.data.ptr = cb;   

   if (epoll_ctl(sess->poll, EPOLL_CTL_MOD, fd, &ev) < 0) {
      cblist[i] = NULL;
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
   }
   return true;

fail:
   if (cb) free(cb);
   return false;
}

bool ndmp_dispatcher_init(
      ndmp_session *sess)
{
   assert(sess);
   num_fds = 0;

   sess->poll = epoll_create1(EPOLL_CLOEXEC);
   if (sess->poll < 0)
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);

   return true;
fail:
   if (sess->poll > -1)   close(sess->poll);
   return false;
}

void ndmp_dispatcher_destroy(
      ndmp_session *sess)
{
   if (!sess) return;
   if (sess->poll > -1) {
     close(sess->poll);
     sess->poll = -1;
   }
   return;
}

bool ndmp_dispatcher(
      ndmp_session *sess)
{
   assert(sess);

   int oldfds = 0;
   bool worked;
   int rc = 0;
   int i = 0;
   struct epoll_event *evs = NULL;
   struct ndmp_callback *cb = NULL;
   memset(cblist, 0, sizeof(*cblist) * MAX_FDS);

   assert(sess->poll > 0);

   while (num_fds > 0 && sess->poll > -1) {
      if (oldfds != num_fds || evs == NULL) {
         evs = realloc(evs, sizeof(*evs)*num_fds);
         if (!evs)
            SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
      }
      rc = epoll_wait(sess->poll, evs, num_fds, -1);
      if (rc < 0 && errno == EINTR) {
         continue;
      }
      else if (rc < 0)
        SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
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

fail:
  if (evs) free(evs);
  return false;
}

/*
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
*/
