#include "manager.h"
#include <limits.h>
#include <sys/resource.h>

static void worker_check_timeout(
    struct ev_loop *loop,
    ev_timer *timer,
    int revents)
{
  CANCELOFF;
  /* This is pretty expensive */
  worker_t *w = timer->data;
  manager_t *m = w->manager;
  connection_t *c;
  ev_tstamp now = ev_now(w->loop);

  pthread_mutex_lock(&m->connection_lock);
  m->connection_lockowner = pthread_self();
  c = m->connections;
  while (c) {
    if (c->worker_number != w->worker_number) {
      c = c->next;
      continue;
    }
    pthread_mutex_unlock(&m->connection_lock);

    if ((now - c->last_activity) > (float)m->timeout) {
      connection_destroy(c);
    }
    pthread_mutex_lock(&m->connection_lock);
    m->connection_lockowner = pthread_self();
    c = c->next;
  }
  pthread_mutex_unlock(&m->connection_lock);
  CANCELON;
}

static int tcp_server(
    char *port)
{
  int fd = -1;
  int yes = 1;
  int rc;
  struct addrinfo hints, *ai = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rc = getaddrinfo(NULL, port, &hints, &ai)) != 0) {
    fprintf(stderr, "Cannot getaddrinfo: %s\n", gai_strerror(rc));
    goto fail;;
  }

  fd = socket(ai->ai_family, ai->ai_socktype|SOCK_CLOEXEC, ai->ai_protocol);
  if (fd < 0) {
    warn("Cannot setup socket");
    goto fail;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
    warn("Cannot setsockopt");
    goto fail;
  }

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
    warn("Cannot bind to socket");
    goto fail;
  }

  if (listen(fd, 16384) < 0) {
    warn("Cannot listen on socke");
    goto fail;
  }

  freeaddrinfo(ai);
  return fd;

fail:
  freeaddrinfo(ai);
  close(fd);
  return -1;
}


static void acceptor_cleanup(
    void *data)
{
  int rc;
  manager_t *m = data;

  rc = pthread_mutex_trylock(&m->lock);
  if (rc == EBUSY &! pthread_equal(m->lockowner, pthread_self())) 
    pthread_mutex_lock(&m->lock);
  pthread_mutex_unlock(&m->lock);

  rc = pthread_mutex_trylock(&m->connection_lock);
  if (rc == EBUSY &! pthread_equal(m->connection_lockowner, pthread_self()))
    pthread_mutex_lock(&m->connection_lock);
  pthread_mutex_unlock(&m->connection_lock);

  pthread_cond_signal(&m->cond);
}

void * acceptor_run(
    void *manager)
{
  manager_t *m = manager;
  int rc;
  int fd = -1;
  connection_t *c;

  pthread_cleanup_push(acceptor_cleanup, m);
  while (1) {
    fd = accept(m->fd, NULL, NULL);
    if (fd < 0) {
      warn("Accept failed"); 
      continue;
    }

    /* Given that new connections are simply added to the top of the 
     * linked list, we can leave it there without much hassle */
    CANCELOFF;
    c = connection_init(fd, m);
    if (!c) {
      close(fd);
      CANCELOFF;
      continue;
    }
    connection_add(c);
    CANCELON;
  }
  pthread_cleanup_pop(1);
  pthread_exit(m);
}


static void worker_check_queue(
    struct ev_loop *loop,
    ev_async *as,
    int revents)
{
  worker_t *w = as->data;
  manager_t *m = w->manager;
  connection_t *c;


  pthread_mutex_lock(&m->connection_lock);
  m->connection_lockowner = pthread_self();
  c = m->connections;
  while (c != NULL && c->worker_number < 0) {
//  while (c != NULL) {
    if (c->worker_number < 0) {
      c->worker_number = w->worker_number;
      ev_io_start(w->loop, &c->io);
    }
    c = c->next;
  }
  pthread_mutex_unlock(&m->connection_lock);
}

static void worker_cleanup(
    void *data)
{
  int rc;
  worker_t *w = data;
  manager_t *m = w->manager;

  rc = pthread_mutex_trylock(&m->lock);
  if (rc == EBUSY &! pthread_equal(m->lockowner, pthread_self())) 
    pthread_mutex_lock(&m->lock);

  for (int i=0; i < m->num_workers; i++) {
    if (m->workers[i] == w) {
      m->workers[i] = NULL;
      break;
    }
  }

  m->num_workers--;
  pthread_mutex_unlock(&m->lock);

  rc = pthread_mutex_trylock(&w->lock);
  if (rc == EBUSY &! pthread_equal(w->lockowner, pthread_self()))
    pthread_mutex_lock(&w->lock);
  w->shutdown = 1;
  pthread_mutex_unlock(&w->lock);

  rc = pthread_mutex_trylock(&m->connection_lock);
  if (rc == EBUSY &! pthread_equal(m->connection_lockowner, pthread_self()))
    pthread_mutex_lock(&m->connection_lock);
  pthread_mutex_unlock(&m->connection_lock);

  pthread_cond_signal(&m->cond);
}



static void * worker_start(
    void * data)
{
  worker_t *w = data;
  manager_t *m = w->manager;
  sigset_t block;

  sigemptyset(&block);
  sigaddset(&block, SIGPIPE);
  pthread_sigmask(SIG_BLOCK, &block, NULL);

  pthread_cleanup_push(worker_cleanup, (void *)w);
  manager_lock(m);
  m->num_workers++;
  manager_unlock(m);


  CANCELON;

  w->qcheck.data = w;
  ev_async_start(w->loop, &w->qcheck);
  w->timer.data = w;
  ev_timer_start(w->loop, &w->timer);
  ev_loop(w->loop, 0);

  pthread_cleanup_pop(1);
}


static void worker_destroy(
    worker_t *w)
{
  ev_loop_destroy(w->loop);
  free(w);
}



static void worker_shutdown(
    worker_t *w)
{
  if (!pthread_equal(w->thread, pthread_self())) {
    pthread_cancel(w->thread);
    pthread_join(w->thread, NULL);
    worker_destroy(w);
  }
  else {
    pthread_exit(w);
  }
}



static worker_t * worker_init(
    manager_t *m,
    int worker_num)
{
  int rc;
  worker_t *w;

  w = malloc(sizeof(worker_t));
  if (!w) {
    warn("Cannot allocate memory for worker %d");
    goto fail;
  }

  w->manager = m;
  w->concurrency = 0;
  w->worker_number = worker_num;
  w->shutdown = 0;

  sha256_init(&w->sha_ctx);

  pthread_mutex_init(&w->lock, NULL);

  w->loop = ev_loop_new(0);
  ev_async_init(&w->qcheck, worker_check_queue);
  ev_timer_init(&w->timer, worker_check_timeout, 2.0, 2.0);
  ev_set_priority(&w->qcheck, EV_MAXPRI);
  /* This is not a protected value */
  m->worker_counter++;

  return w;

fail:
  worker_shutdown(w);
  return NULL;
}


static int worker_run(
    worker_t *w)
{
  int rc;
  rc = pthread_create(&w->thread, NULL, worker_start, w);
  if (rc) {
    warn("Cannot start worker %d", w->worker_number);
    return -1;
  }

  return 0;
}



static void manager_shutdown(
    manager_t *m)
{
  connection_t *c, *n;
  int numw;
  /* Signal shutdown request */
  pthread_mutex_lock(&m->lock);
  numw = m->num_workers;
  pthread_mutex_unlock(&m->lock);
  for (int i=0; i < numw; i++) {
    if (m->workers[i])
      worker_shutdown(m->workers[i]);
  }
  /* Kill off connections */

  c = m->connections;
  while (c) {
    n = c->next;
    connection_destroy(c);
    c = n;
  }  
  return;
}


manager_t * manager_init(
    char *database_path,
    char *hostname,
    char *port,
    int timeout)
{
  struct rlimit lim;
  int numw;
  manager_t *m = NULL;

  m = malloc(sizeof(manager_t));
  if (!m)
    goto fail;
  memset(m, 0, sizeof(manager_t));

  /* Set fd limit to max */
  if (getrlimit(RLIMIT_NOFILE, &lim) < 0) {
    warn("Cannot get limits");
    goto fail;
  }
  lim.rlim_cur = lim.rlim_max;

  if (setrlimit(RLIMIT_NOFILE, &lim) < 0) {
    warn("Cannot set limits");
    goto fail;
  }

  m->hostname = strdup(hostname);

  m->connections = NULL;
  m->max_concurrency = lim.rlim_max;
  m->concurrency_now = 0;
  m->shutdown = 0;
  m->timeout = timeout;

  /* TLS session key */
  if (gnutls_session_ticket_key_generate(&m->ssl_session_key) != 
      GNUTLS_E_SUCCESS) {
    warnx("TLS session key creation failed");
    goto fail;
  }

  /* Setup mutexes and friends */
  pthread_mutex_init(&m->connection_lock, NULL);
  pthread_mutex_init(&m->lock, NULL);
  pthread_cond_init(&m->cond, NULL);

  /* Setup socket */
  m->fd = tcp_server(port);

  /* Setup database */
  m->db = database_open(database_path, DB_RDWR);
  if (!m->db)
    goto fail;

  /* Configure workers */
  numw = NUM_WORKERS;
  m->next_worker;
  m->worker_counter = 0;
  m->workers = calloc(numw, sizeof(worker_t));
  for (int i=0; i < numw; i++) {
    if ((m->workers[i] = worker_init(m, i)) == NULL)
      goto fail;
  }

  return m;

fail:
  manager_destroy(m);
  return NULL;
}

void manager_lock(
    manager_t *m)
{
  pthread_mutex_lock(&m->lock);
  m->lockowner = pthread_self();
}

void manager_unlock(
    manager_t *m)
{
  pthread_mutex_unlock(&m->lock);
}


void manager_run(
    manager_t *m)
{
  int total=0;
  int rc;
  int should_have_workers = NUM_WORKERS;
  worker_t *w = NULL;

  for (int i=0; i < m->worker_counter; i++) {
    rc = worker_run(m->workers[i]);
    if (rc < 0)
      return;
    total++;
  }
  rc = pthread_create(&m->acceptor, NULL, acceptor_run, m);

  pthread_mutex_lock(&m->lock);
  m->lockowner = pthread_self();

  while (1) {
    w = NULL;
    while (m->num_workers == should_have_workers)
      pthread_cond_wait(&m->cond, &m->lock);
    pthread_mutex_unlock(&m->lock);

    for (int i=0; i < should_have_workers; i++) {
      rc = pthread_tryjoin_np(m->workers[i]->thread, (void **)&w);
      if (rc == EBUSY) {
        continue;
      }
      else if (rc == 0) {
        worker_destroy(w);
        m->workers[i] = worker_init(m, m->worker_counter);
        worker_run(w);
        m->worker_counter++;
      }
    }
    pthread_mutex_lock(&m->lock);
    m->lockowner = pthread_self();
  }
}

void manager_destroy(
    manager_t *m)
{
  if (m) {
    /* This will kill workers and connections and free them */
    manager_shutdown(m);
    if (m->db_file)
      free(m->db_file);
    if (m->db)
      database_close(m->db);
    if (m->fd < 0)
      close(m->fd);
    if (m->workers)
      free(m->workers);
    if (m->hostname)
      free(m->hostname);
    pthread_mutex_destroy(&m->lock);
    pthread_cond_destroy(&m->cond);
    gnutls_memset(m->ssl_session_key.data, 0, m->ssl_session_key.size);
    free(m);
  }
}

