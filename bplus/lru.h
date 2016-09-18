#ifndef _LRU_H
#define _LRU_H

#include "config.h"

/* The predefined default size of the lru */
#define LRU_SIZE 10240
/* The maximum number of LRU entries there can be at once */
#define LRU_MAX 1048576
/* Determines how often to flush to btree every time a lookup results in a miss */
/* The value set is the worst case equivalent of 50MiB */
#define LRU_MISS_FLUSH 12800  


typedef struct lru_node_t {
  /* The data is stored in a head/tail queue from the scope of the LRU */
  /* To be at the top height is to be the most frequently used.
   * To be at the bottom height is to be the least frequently used. */
  struct lru_node_t *up;
  struct lru_node_t *down;
  /* The data is stored in a linked list from the hashtable scope */
  struct lru_node_t *right;
  /* The actual data we care about */
  uint32_t key;
  enum verdict verdict;
} lru_node_t;

/* The main LRU structure */
typedef struct lru_t {
  /* The maximum number of entries */
  int size;
  /* This is the size of the hash table typical 1.5 x size */
  int h_size;
  /* Contains the hash pointers */
  lru_node_t **hash;
  /* Contains the raw node data */
  lru_node_t *nodes;
  /* The top of the lru */
  lru_node_t *top;
  /* The bottom of the LRU */
  lru_node_t *bottom;
  /* The lock when contention is a problem */
  pthread_mutex_t lock;
  volatile int64_t hits;
  volatile int64_t misses;
} lru_t;

lru_t * lru_new(int size, int hashsize);
void lru_destroy(lru_t *lru);
enum verdict lru_search(lru_t *lru, uint32_t key);
void lru_insert(lru_t *lru, uint32_t key, enum verdict);
void lru_flush(lru_t *lru);
#endif
