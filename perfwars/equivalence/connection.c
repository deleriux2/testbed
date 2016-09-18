#include "common.h"
#include "connection.h"
#include "manager.h"
#include <netinet/tcp.h>

#define BUFSZ 1024

#define GW(c) { \
  (c->worker_number > -1) ? \
    ((manager_t *)c->manager)->workers[c->worker_number] : NULL \
  }

extern gnutls_certificate_credentials_t cred;

static void update_timer(
    connection_t *c)
{
  worker_t *w = GW(c);
  if (!w)
    return;
  c->last_activity = ev_now(w->loop);
  return;
}

static int tls_prepare(
    connection_t *c)
{
  CANCELOFF;
  int rc;
  const char *p;
  manager_t *m = c->manager;

  /* Create a session object */
  rc = gnutls_init(&c->tls, GNUTLS_SERVER|GNUTLS_NONBLOCK);
  if (rc !=  GNUTLS_E_SUCCESS) {
    warnx("Failed to initialize tls object: %s", gnutls_strerror(rc));
    connection_destroy(c);
    CANCELON;
    return 0;
  }

  /* Set the priorities */
  rc = gnutls_priority_set_direct(c->tls, GNUTLS_CIPHER_PRIORITY, &p);
  if (rc !=  GNUTLS_E_SUCCESS) {
    warnx("Failed to set priorities in tls object: %s", gnutls_strerror(rc));
    connection_destroy(c);
    CANCELON;
    return 0;
  }

  /* Load the Root CA list */
  rc = gnutls_credentials_set(c->tls, GNUTLS_CRD_CERTIFICATE, cred);

  /* Associate this connection with GNUTLS */
  gnutls_transport_set_int(c->tls, c->fd);

  /* session resumption here */
  gnutls_session_ticket_enable_server(c->tls, &m->ssl_session_key);
  CANCELON;
  return 1;
}

static void connection_send(
   struct ev_loop *loop,
   ev_io *io,
   int revents)
{
  CANCELOFF;

  connection_t *c = io->data;
  manager_t *m = c->manager;
  worker_t *w = GW(c);
  int rc;
  char *p;

  update_timer(c);

  while (1) {
    rc = gnutls_record_send(c->tls,
                            &c->send_buffer[c->send_offset],
                            c->send_length - c->send_offset);
    if (rc < 0) {
      if (rc == GNUTLS_E_AGAIN) {
       CANCELON;
        return;
      }
      connection_destroy(c);
      CANCELON;
      return;
    }

    c->send_offset += rc;
    if (c->send_offset >= c->send_length) {
      connection_destroy(c);
      CANCELON;
      return;
    }
  }
  CANCELON;
  return;
}


static void connection_recv(
    struct ev_loop *loop,
    ev_io *io,
    int revents)
{
  CANCELOFF;

  connection_t *c = io->data;
  manager_t *m = c->manager;
  worker_t *w = GW(c);
  int rc;
  char *p;

  update_timer(c);

  unsigned char buf[BUFSZ];
  memset(buf, 0, BUFSZ);

  while (1) {
    memset(buf, 0, BUFSZ);
    rc = gnutls_record_recv(c->tls, buf, BUFSZ);
    /* No more bytes to try */
    if (rc == GNUTLS_E_AGAIN)
      goto fin;
    /* Some other unaccounted for error */
    else if (rc < 0) {
      connection_destroy(c);
      goto fin;
    }
    /* Data to fit into buffer */
    else if (rc > 0) {
      /* If buffer too small, enlarge it */
      if (c->recv_offset + rc > c->recv_length) {
        c->recv_buffer = realloc(c->recv_buffer, c->recv_length + (BUFSZ+1));
        if (!c->recv_buffer) {
          connection_destroy(c);
          goto fin;
        }
        memset(&c->recv_buffer[c->recv_offset], 0, BUFSZ+1);
        c->recv_length+= (BUFSZ+1);
      }
      memcpy(&c->recv_buffer[c->recv_offset], buf, rc);
      c->recv_offset += rc;

      if (!c->req)
        c->req = http_request_init(c);
      rc = http_request_parse(c->req, c->recv_buffer);
      if (rc < 0)
        goto fin;
      else if (rc == 0) {
        /* Need moar */
        continue;
      }
      else {
        http_generate_response(c->req, &c->send_buffer, &c->send_length);
        ev_io_stop(w->loop, &c->io);
        ev_io_init(&c->io, connection_send, c->fd, EV_WRITE);
        ev_io_start(w->loop, &c->io);
        goto fin;
      }
    }
    /* Connection terminated by other side */
    else if (rc == 0 && c->recv_offset == 0) {
      connection_destroy(c);
      goto fin;
    }
  }
fin:
  CANCELON;
  return;
}

static void connection_tls_shake(
    struct ev_loop *loop,
    ev_io *io,
    int revents)
{
  CANCELOFF;

  connection_t *c = io->data;
  manager_t *m = c->manager;
  worker_t *w = GW(c);
  update_timer(c);

  int rc;


  if (!c->tls) {
    if (!tls_prepare(c)) {
      connection_destroy(c);
      CANCELON;
      return;
    }
  }

  rc = gnutls_handshake(c->tls);
  switch (rc) {
    case GNUTLS_E_INTERRUPTED:
    case GNUTLS_E_AGAIN:
    case GNUTLS_E_WARNING_ALERT_RECEIVED:
    case GNUTLS_E_GOT_APPLICATION_DATA:
      if (gnutls_error_is_fatal(rc)) {
        connection_destroy(c);
      }
    break;

    case GNUTLS_E_SUCCESS:
      ev_io_stop(w->loop, &c->io);
      ev_io_init(&c->io, connection_recv, c->fd, EV_READ);
      ev_io_start(w->loop, &c->io);
    break;

    default:
      connection_destroy(c);
    break;
  }

  CANCELON;
  return;
}

connection_t * connection_init(
    int fd,
    void *manager)
{
  connection_t *c = malloc(sizeof(connection_t));
  manager_t *m = NULL;
  int yes = 1;

  if (!c)
    goto fail;

  c->manager = manager;
  m = manager;

  c->worker_number = -1;
  c->fd = fd;
  ev_io_init(&c->io, connection_tls_shake, c->fd, EV_READ);
  c->io.data = c;
  c->tls = NULL;
  c->last_activity = ev_time();

  c->recv_buffer = NULL;
  c->send_buffer = NULL;
  c->recv_offset = 0;
  c->send_offset = 0;
  c->recv_length = 0;
  c->send_length = 0;
  c->last = NULL;

  c->req = NULL;

  /* Set nonblocking property and disable nagle */
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0)
    goto fail;

  if (fcntl(fd, F_SETFL, O_NONBLOCK, 1) < 0)
    goto fail;

  return c;

fail:
  connection_destroy(c);
}


void connection_add(
    connection_t *c)
{
  CANCELOFF;
  manager_t *m = c->manager;
  worker_t *w;
  int worker;

  /* Add to the LL */
  pthread_mutex_lock(&m->connection_lock);
  m->connection_lockowner = pthread_self();
  if (m->connections) {
    c->next = m->connections;
    c->next->last = c;
    c->last = NULL;
    m->connections = c;
  }
  else {
    m->connections = c;
    c->next = NULL;
    c->last = NULL;
  }

  worker = m->next_worker++;

  pthread_mutex_lock(&m->lock);
  m->lockowner = pthread_self();
  m->concurrency_now++;
  pthread_mutex_unlock(&m->lock);

  if (m->next_worker >= m->num_workers)
    m->next_worker = 0;

  c->worker_number = -1;
  w = m->workers[worker];
  w->concurrency++;
  ev_async_send(w->loop, &w->qcheck);
  pthread_mutex_unlock(&m->connection_lock);
  CANCELON;
}


void connection_destroy(
    connection_t *c)
{
  CANCELOFF;
  connection_t *l, *r;
  if (!c) {
    CANCELON;
    return;
  }

  manager_t *m = c->manager;

  connection_disconnect(c);

  pthread_mutex_lock(&m->connection_lock);
  m->connection_lockowner = pthread_self();
  if (c == m->connections) {
    m->connections = c->next;
    if (c->next)
      c->next->last = NULL;
  }
  else {
    c->last->next = c->next;
    if (c->next)
      c->next->last = c->last;
  }
  pthread_mutex_unlock(&m->connection_lock);

  if (c->send_buffer)
    free(c->send_buffer);
  if (c->recv_buffer)
    free(c->recv_buffer);

  if (c->req)
    http_request_destroy(c->req);
  CANCELON;
}

void connection_disconnect(
    connection_t *c)
{
  CANCELOFF;
  worker_t *w = GW(c);
  manager_t *m = c->manager;

  if (c->req) {
    if (c->req->state != HTTP_PARSER_STATE_DONE) {
      printf("Uncontinued request disconnect\n");
      printf("%s", c->recv_buffer);
    }
  }

  pthread_mutex_lock(&m->lock);
  m->lockowner = pthread_self();
  m->concurrency_now--;
  pthread_mutex_unlock(&m->lock);

  if (w)
    w->concurrency--;

  if (c->tls) {
    gnutls_bye(c->tls, GNUTLS_SHUT_WR);
    gnutls_deinit(c->tls);
    c->tls = NULL;
  }
  if (c->fd > -1) {
    if (w)
      ev_io_stop(w->loop, &c->io);
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    c->fd = -1;
  }

  CANCELON;  
}
