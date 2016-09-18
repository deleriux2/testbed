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



typedef struct bbdb {
  /* The main structures */
  int fd;
  pagemap_t *map;
  index_t *index;
  btree_t *tree;
  crypto_t *crypto;
  license_t *license;
  lru_t *lru;
  char *path;
  bool enforce;
  bool detached;

  pthread_rwlock_t lock;
  uint32_t revelation;
  uint32_t version;
  uint16_t num_names;
  char names[BBDH_NAME_NUM][BBDH_NAME_SIZE];
} bbdb_t;


bbdb_t * bbdb_new(char *path);
bbdb_t * bbdb_open(char *path);
void bbdb_close(bbdb_t *bbdb);
enum verdict bbdb_verdict(bbdb_t *bbdb, char *ip);
enum verdict bbdb_insert(bbdb_t *bbdb, char *ip, enum verdict v);
int bbdb_seal(bbdb_t *bbdb, char *privatekey, char *certificate);
char * bbdb_get_name(bbdb_t *bbdb, int num);
int bbdb_get_num_names(bbdb_t *bbdb);
int bbdb_add_name(bbdb_t *bbdb, char *name);
#endif
