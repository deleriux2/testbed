#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include "bbdb.h"

#define LRULOCK
#ifdef LRULOCK
#define LOCK(lru) pthread_mutex_lock(&lru->lock)
#define UNLOCK(lru) pthread_mutex_unlock(&lru->lock)
#define HASH(lru,k) (k % lru->size);

static void lru_promote(bbdb_lru_t *lru, bbdb_lru_node_t *ln);
static void lru_demote(bbdb_lru_t *lru, bbdb_lru_node_t *ln);

static void hash_link(bbdb_lru_t *lru, bbdb_lru_node_t *ln);
static void hash_unlink(bbdb_lru_t *lru, bbdb_lru_node_t *ln);
static bbdb_lru_node_t * hash_search(bbdb_lru_t *lru, uint32_t key);


/* Attach a value to the hash */
static void hash_link(
    bbdb_lru_t *lru,
    bbdb_lru_node_t *ln)
{
  bbdb_lru_node_t *he = NULL;
  LOCK(lru);
  int v = HASH(lru, ln->key);

  he = lru->hash[v];
  if (he == NULL) {
    lru->hash[v] = ln;
    ln->right = NULL;
  }
  else {
    /* Find the rightest node */
    for (he; he->right != NULL; he = he->right);
    he->right = ln;
    ln->right = NULL;
  }
  UNLOCK(lru);
}

static void hash_unlink(
    bbdb_lru_t *lru,
    bbdb_lru_node_t *ln)
{
  LOCK(lru);
  int v = HASH(lru, ln->key);
  bbdb_lru_node_t *he, *last;
  last = NULL;

  he = lru->hash[v];
  /* If its the first entry in the hash, modify the hash table */
  if (he == ln)
    lru->hash[v] = ln->right;
  else if (he == NULL) {
    UNLOCK(lru);
    return;
  }
  else {
    /* Find the node left to this one */
    for (he; he != NULL; he=he->right) {
      if (he == ln) {
        he = last;
        break;
      }
      last = he;
    }
    if (he)
      he->right = ln->right;
    ln->right = NULL;
  }
  UNLOCK(lru);
}

/* Retrieve a node from the hash table */
static bbdb_lru_node_t * hash_search(
    bbdb_lru_t *lru,
    uint32_t key)
{
  assert(lru);
  int v = HASH(lru, key);
  bbdb_lru_node_t *ln = lru->hash[v];

  for (ln; ln != NULL; ln=ln->right) {
    if (ln->key == key)
      return ln;
  }
  return NULL;
}

/* Pushes an entry to the top of the LRU */
static void lru_promote(
    bbdb_lru_t *lru,
    bbdb_lru_node_t *ln)
{
  assert(lru);
  assert(ln);

  LOCK(lru);
  bbdb_lru_node_t *above = NULL;
  bbdb_lru_node_t *below = NULL;
  bbdb_lru_node_t *top = lru->top;

  /* Detach node from chain */
  if (ln->up) {
    above = ln->up;
    above->down = below;
  }
  if (ln->down) {
    below = ln->down;
    below->up = above;
  }

  /* Attach to top of LRU */
  top->up = ln;
  lru->top = ln;
  ln->down = top;
  UNLOCK(lru);
}

/* Detaches node from LRU  */
static void lru_demote(
   bbdb_lru_t *lru,
   bbdb_lru_node_t *ln)
{
  LOCK(lru);
  bbdb_lru_node_t *above;

  if (ln->up) {
    above = ln->up;
    above->down = ln->down;
    ln->up = NULL;
  }
  lru->bottom = above;

  UNLOCK(lru);
}

/* Searches the LRU for a matching entry */
enum verdict lru_search(
    bbdb_lru_t *lru,
    uint32_t key)
{
  bbdb_lru_node_t *ln;

  ln = hash_search(lru, key);
  if (!ln) 
    return NONE;

  lru_promote(lru, ln);
  return ln->verdict;
}

/* Adds an entry to the LRU and promotes it. No checks for dupes are made */
void lru_insert(
   bbdb_lru_t *lru,
   uint32_t key,
   enum verdict verdict)
{
  bbdb_lru_node_t *ln;

  LOCK(lru);
  ln = lru->bottom;
  lru_demote(lru, ln);
  hash_unlink(lru, ln);
  ln->key = key;
  ln->verdict = verdict;
  hash_link(lru, ln);
  lru_promote(lru, ln);
}

/* Allocate the LRU list */
bbdb_lru_t * lru_new(
    int size,
    int hashsize)
{
  assert(size > 128 || size < BBDB_LRU_MAX);
  assert(hashsize > 128 || hashsize < (BBDB_LRU_MAX * 2));

  int i;
  bbdb_lru_t *lru = NULL;
  bbdb_lru_node_t *ln = NULL;
  bbdb_lru_node_t *last = NULL;
  pthread_mutexattr_t attr;

  lru = malloc(sizeof(bbdb_lru_t));
  if (!lru)
    goto fail;
  lru->size = size;
  lru->h_size = hashsize;

  lru->top = NULL;
  lru->bottom = NULL;
  lru->nodes = calloc(size, sizeof(bbdb_lru_node_t));
  if (!lru->nodes)
    goto fail;
  lru->hash = calloc(hashsize, sizeof(bbdb_lru_node_t *));
  if (!lru->hash)
    goto fail;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&lru->lock, &attr);

  /* Set the initial pointers */
  lru->top = &lru->nodes[0];
  lru->bottom = &lru->nodes[size-1];

  /* Iterate over the nodes, setting the lists pointers */
  for (i=0; i < size; i++) {
    ln = &lru->nodes[i];
    ln->up = &lru->nodes[i-1];
    ln->down = &lru->nodes[i+1];
    ln->right = NULL;
    ln->key = 0;
    ln->verdict = ERROR;    
  }
  /* Repoint first and last */
  lru->nodes[0].up = NULL;
  lru->nodes[lru->size-1].down = NULL;

  return lru;

fail:
  if (lru) {
    free(lru);
    if (lru->nodes)
      free(lru->nodes);
    if (lru->hash)
      free(lru->hash);
  }
  return NULL;
}


/* The caller must ensure that you dont destroy this whilst others
 * are still using it! */
void lru_destroy(
    bbdb_lru_t *lru)
{
  assert(lru);
  if (lru) {
    if (lru->nodes)
      free(lru->nodes);
    if (lru->hash)
      free(lru->hash);
    free(lru);
  }
}

/* Clears the entire cache */
void lru_flush(
    bbdb_lru_t *lru)
{
  int i;
  bbdb_lru_node_t *ln = NULL;

  LOCK(lru);
  memset(lru->hash, 0, sizeof(bbdb_lru_node_t *) * lru->h_size);
  memset(lru->nodes, 0, sizeof(bbdb_lru_node_t) * lru->size);

  for (i=0; i < lru->size; i++) {
    ln = &lru->nodes[i];
    ln->up = &lru->nodes[i-1];
    ln->down = &lru->nodes[i+1];
    ln->right = NULL;
    ln->key = 0;
    ln->verdict = ERROR;    
  }
  /* Repoint first and last */
  lru->nodes[0].up = NULL;
  lru->nodes[lru->size-1].down = NULL;

  UNLOCK(lru);
}

#endif
#undef LRULOCK



#define TOTALKEYS 6
#ifndef CONFIG_H
int main() {
  int i,k;
  bbdb_lru_t *lru = NULL;

  lru = lru_new(TOTALKEYS, TOTALKEYS+(TOTALKEYS/2));
  lru_flush(lru);

  for (i=0; i < TOTALKEYS; i++) {
    lru_insert(lru, i*6, DROP);
  }

  for (i=0; i < TOTALKEYS; i++) {
    if ((k = lru_search(lru, i*6)) != NONE) {
      printf("%d %d\n", i*6,k);
    }
  }
}
#endif
