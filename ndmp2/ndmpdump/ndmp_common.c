#include "common.h"
#include "ndmp.h"
#include "ndmp_error.h"
#include "ndmp_common.h"

#include <sys/mman.h>

static int _ndmp_read(void *data, void *buf, int len);
static int _ndmp_write(void *data, void *buf, int len);

ndmp_session *ndmp_init_session()
{
   ndmp_session *sess = NULL;
   sess = malloc(sizeof(*sess));
   if (!sess)
     goto fail;
   memset(sess, 0, sizeof(*sess));

   sess->fd = -1;
   sess->seqno = 0;
   sess->numfds = 0;
   sess->peer_seqno = 0;
   sess->mover = NULL;
   sess->error = NDMP_NO_ERR;
   sess->err_major = 0;
   sess->err_minor = 0;
   sess->err_text = NULL;

   memset(sess->username, 0, sizeof(sess->username));
   memset(sess->password, 0, sizeof(sess->password));
   memset(sess->peerhost, 0, sizeof(sess->peerhost));
   memset(sess->peerport, 0, sizeof(sess->peerport));
   memset(sess->moverhost, 0, sizeof(sess->moverhost));
   memset(sess->moverport, 0, sizeof(sess->moverport));

   sess->fs = NULL;
   sess->fs_len = 0;
   sess->bu = NULL;
   sess->bu_len = 0;

   if (!ndmp_dispatcher_init(sess))
     goto fail;

   xdrrec_create(&sess->xdrs, 0, 0, (void *)sess, _ndmp_read, _ndmp_write);
   xdrrec_skiprecord(&sess->xdrs);
   return sess;

fail:
   ndmp_dispatcher_destroy(sess);
   return NULL;
}


void ndmp_free_session(ndmp_session *sess) {
   int i;
   if (!sess) return;
   shutdown(sess->fd, SHUT_RDWR);
   close(sess->fd);
   ndmp_dispatcher_destroy(sess);
   ndmp_mover_destroy(sess);
   if (sess->err_text)
     free(sess->err_text);

   for (i=0; i < sess->fs_len; i++) {
      if (sess->fs[i].envs)
         free(sess->fs[i].envs);
   }
   if (sess->fs)
      free(sess->fs);

   for (i=0; i < sess->bu_len; i++) {
      if (sess->bu[i].envs)
         free(sess->bu[i].envs);
   }
   if (sess->bu)
      free(sess->bu);

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

   rc = send(sess->fd, buf, len, MSG_NOSIGNAL);
   if (rc < 0) {
      goto end;
   }

   else if (rc == 0) {
      errno = ENODATA;
      rc = -1;
      goto end;
   }
end:
   return rc;
}

