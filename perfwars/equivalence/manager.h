#ifndef _MANAGER_H
#define _MANAGER_H
#include "common.h"
#include "database.h"
#include "connection.h"
#include <nettle/sha2.h>

#define NUM_WORKERS sysconf(_SC_NPROCESSORS_ONLN)
//#define NUM_WORKERS 4

#define CANCELOFF pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#define CANCELON pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)

typedef struct worker worker_t;
typedef struct manager manager_t;


typedef struct worker {
  pthread_t thread;
  manager_t *manager;

  int concurrency;
  int worker_number;
  int shutdown;

  struct ev_loop *loop;
  ev_async qcheck;
  ev_timer timer;

  struct sha256_ctx sha_ctx;

  pthread_mutex_t lock;
  pthread_t lockowner;
} worker_t;


typedef struct manager {
  int max_concurrency;
  int concurrency_now;
  int shutdown;
  int fd;

  gnutls_datum_t ssl_session_key;

  int timeout;
  int next_worker;
  int worker_counter;
  int num_workers;
  worker_t **workers;

  char *hostname;
  char *db_file;
  db_t *db;

  connection_t *connections;

  pthread_t acceptor;
  pthread_mutex_t connection_lock;
  pthread_t connection_lockowner;
  pthread_mutex_t lock;
  pthread_t lockowner;
  pthread_cond_t cond;
  
} manager_t;

manager_t * manager_init(char *database_path, char *hostname, char *port, int timeout);
void manager_destroy(manager_t *m);
void manager_lock(manager_t *m);
void manager_unlock(manager_t *m);
void manager_run(manager_t *m);

#endif
