#include "common.h"
#include "manager.h"
#include "worker.h"
#include "connection.h"
#include "http.h"
#include "ippool.h"
#include <ev.h>

/* This is the max record size possible to fetch */
#define BUFSZ 122880 
#define REQUEST "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: perfwars_v0\r\nConnection: close\r\n\r\n"

extern gnutls_certificate_credentials_t cred;

static void connection_recv(
    struct ev_loop *l,
    ev_io *io,
    int revents)
{
  CANCELOFF;

  connection_t *c = io->data;
  worker_t *w = c->worker;
  manager_t *m = c->manager;
  round_t *r = c->round;
  connection_stats_t *s = c->stats;
  int rc, rc2;
  unsigned char buf[BUFSZ];
  memset(buf, 0, BUFSZ);
  int count=1;

  if (s->first_byte_time.tv_sec == 0)
    gettimeofday(&s->first_byte_time, NULL);

  while (count) {
    rc = gnutls_record_recv(c->tls, buf, BUFSZ);
    //printf("rc: %d, w: %d, c: %d\n", rc, w->worker_number, count);
    if (rc < 0 && rc != GNUTLS_E_PREMATURE_TERMINATION &&
        rc != GNUTLS_E_AGAIN) {
      s->error_code = RECV_FAILED;
      connection_disconnect(w, c);
      CANCELON;
      return;
    }
    else if (rc > 0) {
      /* If buffer too small, enlarge it */
      if (c->recv_buffer_offset + rc > c->recv_buffer_len) {
        c->recv_buffer = realloc(c->recv_buffer, c->recv_buffer_len + (BUFSZ+1));
        if (!c->recv_buffer) {
          s->error_code = RECV_FAILED;
          connection_disconnect(w, c);
          CANCELON;
          return;
        }
        memset(&c->recv_buffer[c->recv_buffer_offset], 0, BUFSZ+1);
        c->recv_buffer_len += (BUFSZ+1);
      }
      memcpy(&c->recv_buffer[c->recv_buffer_offset], buf, rc);
      c->recv_buffer_offset += rc;
      count++;
      continue;
    }

    /* Connection terminated by other side */
    else if (rc == 0 && c->recv_buffer_offset == 0) {
      s->error_code = RECV_FAILED;
      connection_disconnect(w, c);
      CANCELON;
      return;
    }

    /* Completed */
    if (rc == 0 || (rc < 0 && rc == GNUTLS_E_PREMATURE_TERMINATION)) {
      s->error_code = VALIDATION_TIMED_OUT;
      if ((rc2 = http_validate(c)) == 0) {
        s->error_code = SUCCESS;
        pthread_mutex_lock(&r->lock);
        r->actual_concurrency++;
        if (r->actual_concurrency == r->concurrency)
          gettimeofday(&r->round_end, NULL);
        pthread_mutex_unlock(&r->lock);
      }
      else {
        s->error_code = VALIDATION_FAILED;
        //printf("\n\n%s\n\n%s\n\n", c->send_buffer, c->recv_buffer);
      }
      connection_disconnect(w, c);
      CANCELON;
      return;
    }

    /* Ran out of data to recv */
    if (rc < 0 && rc == GNUTLS_E_AGAIN) {
      CANCELON;
      return;
    }
  }
  CANCELON;
  return;
}


static void connection_send(
    struct ev_loop *l,
    ev_io *io,
    int revents)
{
  CANCELOFF;

  connection_t *c = io->data;
  worker_t *w = c->worker;
  manager_t *m = c->manager;
  connection_stats_t *s = c->stats;
  int rc;

  while (1) {
    rc = gnutls_record_send(c->tls, 
                            &c->send_buffer[c->send_buffer_offset], 
                            c->send_buffer_len - c->send_buffer_offset);
    if (rc < 0) {
      if (rc == GNUTLS_E_AGAIN) {
        CANCELON;
        return;;
      }
      s->error_code = SEND_FAILED;
      connection_disconnect(w, c);
      CANCELON;
      return;
    }

    c->send_buffer_offset += rc;
    if (c->send_buffer_offset >= c->send_buffer_len) {
      gettimeofday(&s->send_time, NULL);
      ev_io_stop(w->loop, &c->io);
      ev_io_init(&c->io, connection_recv, c->fd, EV_READ);
      ev_io_start(w->loop, &c->io);
      s->error_code = RECV_TIMED_OUT;
      CANCELON;
      return;
    }
  }
  CANCELON;
  return;  
  
}


static int connection_prepare_send(
    connection_t *c)
{
  worker_t *w = c->worker;
  manager_t *m = c->manager;
  connection_stats_t *s = c->stats;

  if (c->send_buffer)
    free(c->send_buffer);

  if (http_generate_record(c)) {
    s->error_code = SEND_TIMED_OUT;
    connection_disconnect(w, c);
    return -1;
  }

  return 0;
}

static void connection_ssl(
    struct ev_loop *l,
    ev_io *io,
    int revents)
{
  CANCELOFF;

  connection_t *c = io->data;
  worker_t *w = c->worker;
  manager_t *m = c->manager;
  connection_stats_t *s = c->stats;
  int rc;

  if (s->ssl_start.tv_sec == 0)
    gettimeofday(&s->ssl_start, NULL);
  rc = gnutls_handshake(c->tls);
  switch (rc) {
    case GNUTLS_E_INTERRUPTED:
    case GNUTLS_E_AGAIN:
    case GNUTLS_E_WARNING_ALERT_RECEIVED:
    case GNUTLS_E_GOT_APPLICATION_DATA:
      if (gnutls_error_is_fatal(rc)) {
        s->error_code = SSL_FAILED;
        connection_disconnect(w, c);
        return;
      }
      CANCELON;
      return;
    break;

    case GNUTLS_E_SUCCESS:
      gettimeofday(&s->ssl_end, NULL);
      /* This often never seems to work.. */
      if (!gnutls_session_is_resumed(c->tls)) { 
        rc = gnutls_session_get_data2(c->tls, &w->session_key);
      }
      s->error_code = SEND_TIMED_OUT;
      /* Prepare the send buffer */
      if (connection_prepare_send(c) < 0) {
        CANCELON;
        return;
      }
      ev_io_stop(w->loop, &c->io);
      ev_io_init(&c->io, connection_send, c->fd, EV_WRITE);
      ev_io_start(w->loop, &c->io);
    break;

    default:
      s->error_code = SSL_FAILED;
      connection_disconnect(w, c);
      CANCELON;
      return;
    break;
  }
}

static void connection_ssl_setup(
    connection_t *c)
{
  CANCELOFF;

  worker_t *w = c->worker;
  manager_t *m = c->manager;
  connection_stats_t *s = c->stats;
  const char *p;
  int rc;


  s->error_code = SSL_TIMED_OUT;
  /* Create a session object */
  rc = gnutls_init(&c->tls, GNUTLS_CLIENT|GNUTLS_NONBLOCK);
  if (rc !=  GNUTLS_E_SUCCESS) {
    s->error_code = SSL_FAILED;
    connection_disconnect(w, c);
    CANCELON;
    return;
  }

  /* Set the priorities */
  rc = gnutls_priority_set_direct(c->tls, GNUTLS_CIPHER_PRIORITY, &p);
  if (rc !=  GNUTLS_E_SUCCESS) {
    s->error_code = SSL_FAILED;
    connection_disconnect(w, c);
    CANCELON;
    return;
  }

  /* Load the Root CA list */
  rc = gnutls_credentials_set(c->tls, GNUTLS_CRD_CERTIFICATE, cred);

  /* Associate this connection with GNUTLS */
  gnutls_transport_set_int(c->tls, c->fd);

  /* Setup SNI */
  rc = gnutls_server_name_set(c->tls, GNUTLS_NAME_DNS, m->hostname, 
                              strlen(m->hostname));
  if (rc !=  GNUTLS_E_SUCCESS) {
    s->error_code = SSL_FAILED;
    connection_disconnect(w, c);
    CANCELON;
    return;
  }

  /* Fetch the workers session resumption ticket */
  if (w->session_key.size) {
    rc = gnutls_session_set_data(c->tls, w->session_key.data,
                                 w->session_key.size);
    if (rc != GNUTLS_E_SUCCESS) {
      s->error_code = SSL_FAILED;
      connection_disconnect(w, c);
      CANCELON;
      return;
    }
  }
}

static void connection_end_connect(
    struct ev_loop *l,
    ev_io *io,
    int revents)
{
  CANCELOFF;
  int eno, len=sizeof(int);
  connection_t *c = io->data;
  worker_t *w = c->worker;
  connection_stats_t *s = c->stats;

  if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &eno, &len) < 0) {
    s->error_code = CONNECTION_FAILED;
    connection_disconnect(w, c);
  }

  if (eno != 0) {
    s->error_code = CONNECTION_FAILED;
    connection_disconnect(w, c);
  }
  else {
    gettimeofday(&s->connect_time, NULL);
    len = sizeof(struct sockaddr_in6);
    getsockname(c->fd, &c->src, &len);
    s->error_code = SSL_TIMED_OUT;
    ev_io_stop(w->loop, &c->io);
    ev_set_priority(&c->io, 0);
    connection_ssl_setup(c);
    ev_io_init(&c->io, connection_ssl, c->fd, EV_WRITE|EV_READ);
    ev_io_start(w->loop, &c->io);
  }
  CANCELON;
  return;
}

void connection_clear_buffers(
    connection_t *c)
{
  if (c->send_buffer) {
    free(c->send_buffer);
    c->send_buffer = NULL;
    c->send_buffer_len = 0;
    c->send_buffer_offset = 0;
  }
  if (c->recv_buffer) {
    free(c->recv_buffer);
    c->recv_buffer = NULL;
    c->recv_buffer_len = 0;
    c->recv_buffer_offset = 0;
  }
  if (c->canvas_sha) {
    free(c->canvas_sha);
    c->canvas_sha = NULL;
  }
  if (c->canvas_filename) {
    free(c->canvas_filename);
    c->canvas_filename = NULL;
  }
  if (c->resp) {
    http_response_destroy(c->resp);
    c->resp = NULL;
  }

  c->canvas_offset = 0;
  c->canvas_len = 0;

}

void connection_disconnect(
    worker_t *w,
    connection_t *c)
{
  CANCELOFF;
  /* IIS just terminates, so just shudown one way */ 
  connection_stats_t *s = c->stats;

  gettimeofday(&s->end_time, NULL);
  if (c->tls) {
    gnutls_bye(c->tls, GNUTLS_SHUT_WR);
    gnutls_deinit(c->tls);
    c->tls = NULL;
  }
  if (c->fd > -1) {
    ev_io_stop(w->loop, &c->io);
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    c->fd = -1;
  }
  CANCELON;
}

void connection_start_connect(
    worker_t *w,
    connection_t *c)
{
  CANCELOFF;
  pthread_mutex_lock(&c->lock);
  manager_t *m = c->manager;
  connection_stats_t *s = c->stats;
  round_t *r = c->round;
  struct sockaddr_in6 *src, *dst;

  gettimeofday(&s->init_time, NULL);
  src = ippool_next(m->pool_srcs);
  if (bind(c->fd,(struct sockaddr *)src, sizeof(struct sockaddr_in6)) < 0) {
    s->error_code = NOT_STARTED;
    connection_disconnect(w, c);
    CANCELON;
    return;
  }

  dst = ippool_next(m->pool_dsts);
  c->dst = dst;
  if (connect(c->fd, (struct sockaddr *)dst, sizeof(struct sockaddr_in6)) < 0) {
    if (errno == EINPROGRESS) {
      pthread_mutex_lock(&r->lock);
      r->attempted_concurrency++;
      if (r->attempted_concurrency == r->concurrency)
        gettimeofday(&r->attempt_end, NULL);
      pthread_mutex_unlock(&r->lock);
      ev_io_init(&c->io, connection_end_connect, c->fd, EV_WRITE);
      c->io.data = c;
      ev_set_priority(&c->io, 1);
      ev_io_start(w->loop, &c->io);
      s->error_code = CONNECTION_TIMED_OUT;
    }
    else {
      s->error_code = CONNECTION_FAILED;
      connection_disconnect(w, c);
    }
  }
  else {
    pthread_mutex_lock(&r->lock);
    r->attempted_concurrency++;
      if (r->attempted_concurrency == r->concurrency)
        gettimeofday(&r->attempt_end, NULL);
    pthread_mutex_unlock(&r->lock);
    gettimeofday(&s->connect_time, NULL);
    s->error_code = SSL_TIMED_OUT;
    ev_io_init(&c->io, connection_ssl, c->fd, EV_READ);
    c->io.data = c;
    ev_io_start(w->loop, &c->io);
  }

  pthread_mutex_unlock(&c->lock);
  CANCELON;
  return;
}
