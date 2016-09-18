#ifndef _BBDB_H
#define _BBDB_H

#include "config.h"
#include "page.h"
#include "index.h"
#include "btree.h"
#include "license.h"
#include "crypto.h"
#include "lru.h"

#define BBDB_VERSION 1
#define BBDH_NAME_SIZE 32
#define BBDH_NAME_NUM  32

#define MERGE_TYPE_CHANGED 0
#define MERGE_TYPE_ADDED   1
#define MERGE_TYPE_FREED   2


typedef struct bbdb {
  /* The main structures */
  int fd;
  pagemap_t *map;
  index_t *index;
  btree_t *deny;
  btree_t *allow;
  crypto_t *crypto;
  license_t *license;
  lru_t *lru;
  char *path;
  volatile bool enforce;
  volatile int detached;
  volatile int workers;
  pthread_cond_t cond;
  pthread_mutex_t lock;

  uint32_t revelation;
  uint32_t version;
} bbdb_t;

typedef struct bbdb_diff_record {
  uint64_t pageno;
  char checksum[SHA256_DIGEST_LENGTH];
} bbdb_diff_record_t;

typedef struct bbdb_merge_record {
  char type;
  int64_t pageno;
  int64_t new_pageno;
  uint64_t magic;
  char checksum[SHA256_DIGEST_LENGTH];
  char data[DATALEN];
} bbdb_merge_record_t;

typedef struct bbdb_diff_summary {
  bbdb_t *bbdb;
  int32_t current_page;

  uint32_t version;
  uint32_t revelation;
  int64_t pagecount;
} bbdb_diff_summary_t;

typedef struct bbdb_merge_summary {
  bbdb_t *bbdb;
  int64_t last_pageno;
  int64_t their_pagecount;
  int64_t add_pageno;
 
  uint32_t version;
  uint32_t revelation;
  int64_t pagecount;
  int32_t changed;
  int32_t added;
  int32_t freed;
  int32_t numrecs;
  int64_t allow_nodes;
  int64_t deny_nodes;
  int64_t allow_recs;
  int64_t deny_recs;
  int64_t allow_offset;
  int64_t deny_offset;
} bbdb_merge_summary_t;

static inline void bbdb_detach(bbdb_t *bbdb);
static inline void bbdb_attach(bbdb_t *bbdb);
static inline int  bbdb_detatched(bbdb_t *bbdb);


/* Inlines */
static inline int bbdb_detached(
    bbdb_t *bbdb)
{
  assert(bbdb);
  /* Not detached */
  int state;
  state = bbdb->detached;
  if (state < 0)
    return 0;

  /* Is detached */
  else if (state == 0)
    return 1;

  /* Is detaching. Wait for all parties to signal
     the semaphore and continue */
  else {
    pthread_mutex_lock(&bbdb->lock);
    bbdb->detached--;
    if (bbdb->detached == 0) 
      pthread_cond_broadcast(&bbdb->cond);
    else 
      pthread_cond_wait(&bbdb->cond, &bbdb->lock);

    pthread_mutex_unlock(&bbdb->lock);
    return 1;
  }
}

/* Waits for all parties to be detached from the db */
static inline void bbdb_detach(
    bbdb_t *bbdb)
{
  /* Is already in a detached state */
  if (bbdb->detached >= 0)
    return;

  pthread_mutex_lock(&bbdb->lock);
  bbdb->detached = bbdb->workers-1;
  /* Wait until all workers have signalled they are out
     of the critical section */
  if (bbdb->detached > 0)
    pthread_cond_wait(&bbdb->cond, &bbdb->lock);
  pthread_mutex_unlock(&bbdb->lock);
  return;
}

/* Makes the database available again */
static inline void bbdb_attach(
    bbdb_t *bbdb)
{
  pthread_mutex_lock(&bbdb->lock);
  bbdb->detached = -1;
  pthread_mutex_unlock(&bbdb->lock);
}



bbdb_t * bbdb_new(char *path);
bbdb_t * bbdb_open(char *path);
void bbdb_close(bbdb_t *bbdb);
enum verdict bbdb_verdict(bbdb_t *bbdb, char *ip);
int bbdb_insert(bbdb_t *bbdb, char *ip, char *ip2, enum verdict v);
int bbdb_seal(bbdb_t *bbdb, char *privatekey, char *certificate);
char * bbdb_get_name(bbdb_t *bbdb, int num);
int bbdb_get_num_names(bbdb_t *bbdb);
int bbdb_add_name(bbdb_t *bbdb, char *name);
void bbdb_vacuum(bbdb_t *bbdb);
void bbdb_import(bbdb_t *dst, bbdb_t *src);
int bbdb_diff_next(bbdb_diff_summary_t *summ, bbdb_diff_record_t *diff);
int bbdb_diff_init(bbdb_t *bbdb, bbdb_diff_summary_t *diff);
int bbdb_merge_next(bbdb_merge_summary_t *summ, bbdb_diff_record_t *diff, bbdb_merge_record_t *merge);
int bbdb_merge_init(bbdb_t *bbdb, bbdb_merge_summary_t *merge, bbdb_diff_summary_t *summ);
int bbdb_merge_new(bbdb_merge_summary_t *summ, bbdb_merge_record_t *merge);
int bbdb_apply_merge_init(bbdb_t *bbdb, bbdb_merge_summary_t *merge);
int bbdb_apply_merge_next(bbdb_merge_summary_t *summ, bbdb_merge_record_t *merge);
void bbdb_connect(bbdb_t *bbdb);
void bbdb_disconnect(bbdb_t *bbdb);

#endif
