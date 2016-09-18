#ifndef _WORKER_H
#define _WORKER_H
#include "common.h"
#include <nettle/sha2.h>
#include <ev.h>

typedef struct worker {
  pthread_t thread;
  void *manager;
  int worker_number;
  int seed;

  struct sha256_ctx sha_ctx;

  struct ev_loop *loop;
  ev_async finish;

  gnutls_datum_t session_key;
} worker_t;


void * worker_spawn(void *manager, int num, int *seed);

#endif
