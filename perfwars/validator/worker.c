#include "common.h"
#include "manager.h"
#include "worker.h"
#include "connection.h"
#include <netinet/tcp.h>
/*
typedef struct connection {
  pthread_mutex_t lock;

  struct sockaddr addrdata;
  size_t addrlen;
  int fd;
  void *stats;
  void *round;
  void *manager;
  void *callback;
} connection_t;
*/

static void worker_break_loop(
    struct ev_loop *l,
    ev_async *fin,
    int revents)
{
  ev_break(l, EVBREAK_ALL);
}

static void worker_begin_round(
    worker_t *w,
    round_t *r)
{
  manager_t *m = w->manager;
  connection_t *c;

  /* Wait until we receive the signal to start */
  pthread_mutex_lock(&r->lock);
  while (r->round_start.tv_sec == 0)
    pthread_cond_wait(&m->worker_cond, &r->lock);
  pthread_mutex_unlock(&r->lock);

  for (int i=w->worker_number; i < r->concurrency; i += m->num_workers) {
    c = &r->connections[i];
    connection_start_connect(w, c);
  }

  ev_run(w->loop, 0);
  pthread_mutex_lock(&r->lock);
  r->worker_finished--;
  if (r->worker_finished == 0)
    pthread_cond_signal(&m->manager_cond);
  pthread_mutex_unlock(&r->lock);

  /* Wait for a signal from the manager before
   * moving onto the next round */
  pthread_mutex_lock(&r->lock);
  while (m->current_round == r->round_number)
    pthread_cond_wait(&m->worker_cond, &r->lock);
  pthread_mutex_unlock(&r->lock);
  return;
}

static int worker_prepare_connections(
    worker_t *w,
    round_t *r)
{
  manager_t *m = w->manager;
  connection_t *c;
  int yes=1;

  for (int i=w->worker_number; i < r->concurrency; i += m->num_workers) {
    c = &r->connections[i];
    c->fd = socket(AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, 0);
    if (c->fd < 0) 
      err(EXIT_FAILURE, "Unable to prepare socket in worker %d connection %d",
          w->worker_number, i);
    c->worker = w;
    if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0)
      err(EXIT_FAILURE, "Unable to prepare socket in worker %d connection %d");
  }

  ev_async_start(w->loop, &w->finish);

  /* Decrement worker ready to signal we are prepared.. */
  pthread_mutex_lock(&r->lock);
  r->worker_finished--;
  if (r->worker_finished == 0)
    pthread_cond_signal(&m->manager_cond);
  pthread_mutex_unlock(&r->lock);
}

static void * worker_work(
    void *data)
{
  worker_t *w = data;
  round_t *r = NULL;
  manager_t *m = w->manager;

  struct sigaction act;
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGPIPE);
  memset(&act, 0, sizeof(act));

  act.sa_handler = SIG_IGN;
  if (sigaction(SIGPIPE, &act, NULL) < 0)
    err(EXIT_FAILURE, "Worker couldn't ignore pipes");

  pthread_sigmask(SIG_BLOCK, &block, NULL);

 /* Keep going until all rounds are finished */
  while (m->current_round <= m->num_rounds) {
    r = &m->rounds[m->current_round];
    worker_prepare_connections(w, r);
    worker_begin_round(w, r);
  }
  pthread_exit(NULL);
}

void * worker_spawn(
    void *manager,
    int num,
    int *seed)
{
  worker_t *w = malloc(sizeof(*w));
  if (!w)
    NULL;

  w->manager = manager;
  w->seed = rand_r(seed);
  w->worker_number = num;
  w->loop = ev_loop_new(0);
  w->session_key.data = NULL;
  w->session_key.size = 0;
  ev_async_init(&w->finish, worker_break_loop);
  w->finish.data = w;
  ev_set_priority(&w->finish, EV_MAXPRI);

  sha256_init(&w->sha_ctx);

  if (pthread_create(&w->thread, NULL, worker_work, w) != 0)
    return NULL;

  return w;
}
