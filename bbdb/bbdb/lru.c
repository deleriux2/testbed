#include "lru.h"
#ifndef LRULOCK
#define LRULOCK
#ifdef LRULOCK
#define LOCK(lru) // pthread_mutex_lock(&lru->lock)
#define UNLOCK(lru) // pthread_mutex_unlock(&lru->lock)
#define HASH(lru,k) (k % lru->size);

static int lru_size = LRU_SIZE;
static int lru_h_size = LRU_SIZE + (LRU_SIZE/2);
static lru_real_t **lrus = NULL;
static int lru_num = 0;
pthread_mutex_t lru_global = PTHREAD_MUTEX_INITIALIZER;

static lru_real_t * get_lru(lru_t *key);
static lru_node_t * hash_search(lru_real_t *lru, uint32_t key);
static lru_real_t * lru_real_new(int size, int hashsize);
static void hash_link(lru_real_t *lru, lru_node_t *ln);
static void hash_unlink(lru_real_t *lru, lru_node_t *ln);
static void lru_demote(lru_real_t *lru, lru_node_t *ln);
static void lru_promote(lru_real_t *lru, lru_node_t *ln);
static void lru_real_destroy(void *data);
static void lru_real_flush(lru_real_t *lru);


static lru_real_t * get_lru(
   lru_t *key)
{
  lru_real_t *lru = pthread_getspecific(*key);
  if (!lru) {
    /* Allocate the LRU in this case */
    lru = lru_real_new(lru_size, lru_h_size);
    pthread_mutex_lock(&lru_global);
    lrus = realloc(lrus, sizeof(lru_real_t *) * (lru_num +1));
    lrus[lru_num] = lru;
    lru_num++;
    pthread_mutex_unlock(&lru_global);
    if (!lrus)
      abort();
    pthread_setspecific(*key, lru);
  }
  return lru;
}


static lru_node_t * hash_search(
    lru_real_t *lru,
    uint32_t key)
{
  assert(key);
  int v = HASH(lru, key);
  lru_node_t *ln = lru->hash[v];

  for (ln; ln != NULL; ln=ln->right) {
    if (ln->key == key)
      return ln;
  }
  return NULL;
}


static lru_real_t * lru_real_new(
    int size,
    int hashsize)
{
  assert(size > 128 || size < LRU_MAX);
  assert(hashsize > 128 || hashsize < (LRU_MAX * 2));

  int i;
  lru_real_t *lru = NULL;
  lru_node_t *ln = NULL;
  lru_node_t *last = NULL;
  pthread_mutexattr_t attr;

  lru = malloc(sizeof(lru_real_t));
  if (!lru)
    goto fail;
  lru->size = size;
  lru->h_size = hashsize;

  lru->top = NULL;
  lru->bottom = NULL;
  lru->nodes = NULL;
  lru->hash = NULL;
  lru->hash = calloc(lru->h_size, sizeof(lru_node_t *));
  if (!lru->hash)
    goto fail;
  lru->nodes = calloc(lru->size, sizeof(lru_node_t));
  if (!lru->nodes)
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

  /* Affix top and bottom */
  lru->top = &lru->nodes[0];
  lru->bottom = &lru->nodes[lru->size-1];

  return lru;

fail:
  if (lru) {
    if (lru->nodes)
      free(lru->nodes);
    if (lru->hash)
      free(lru->hash);
    free(lru);
  }
  return NULL;
}


static void hash_link(
    lru_real_t *lru,
    lru_node_t *ln)
{
  lru_node_t *he = NULL;
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
    lru_real_t *lru,
    lru_node_t *ln)
{
  LOCK(lru);
  int v = HASH(lru, ln->key);
  lru_node_t *he, *last;
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


static void lru_demote(
   lru_real_t *lru,
   lru_node_t *ln)
{
  assert(lru);
  assert(ln);

  LOCK(lru);
  lru_node_t *above = ln->up;
  lru_node_t *below = ln->down;

  if (above) {
    above->down = ln->down;
    ln->up = NULL;
  }
  if (below) {
    below->up = above;
    ln->down = NULL;
  }
  lru->bottom = above;

  UNLOCK(lru);
}


static void lru_promote(
    lru_real_t *lru,
    lru_node_t *ln)
{
  assert(lru);
  assert(ln);

  LOCK(lru);
  lru_node_t *above = ln->up;
  lru_node_t *below = ln->down;
  lru_node_t *top = lru->top;

  /* Detach node from chain */
  if (above) {
    above = ln->up;
    above->down = below;
  }
  if (below) {
    below = ln->down;
    below->up = above;
  }

  /* Attach to top of LRU */
  top->up = ln;
  lru->top = ln;
  ln->down = top;
  UNLOCK(lru);
}


static void lru_real_destroy(
    void *data)
{
  assert(data);
  lru_real_t *lru = (lru_real_t *)data;
  if (lru) {
    if (lru->nodes)
      free(lru->nodes);
    if (lru->hash)
      free(lru->hash);
    free(lru);
  }
}


static void lru_real_flush(
    lru_real_t *lru)
{
  int i;
  lru_node_t *ln = NULL;

  LOCK(lru);
  memset(lru->hash, 0, sizeof(lru_node_t *) * lru->h_size);
  memset(lru->nodes, 0, sizeof(lru_node_t) * lru->size);

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




/* Searches the LRU for a matching entry */
enum verdict lru_search(
    lru_t *pkey,
    uint32_t key)
{
  lru_real_t *lru = get_lru(pkey);
  lru_node_t *ln;

  ln = hash_search(lru, key);
  if (!ln) {
    ATOMIC_INC(lru->misses);
    return NOTFOUND;
  }

  lru_promote(lru, ln);
  ATOMIC_INC(lru->hits);
  return ln->verdict;
}

/* Adds an entry to the LRU and promotes it. No checks for dupes are made */
void lru_insert(
   lru_t *pkey,
   uint32_t key,
   enum verdict verdict)
{
  lru_real_t *lru = get_lru(pkey);
  lru_node_t *ln;

  LOCK(lru);
  ln = lru->bottom;
  hash_unlink(lru, ln);
  ln->key = key;
  ln->verdict = verdict;
  hash_link(lru, ln);
  lru_promote(lru, ln);
  UNLOCK(lru);
}

/* Set the LRU main values */
lru_t * lru_new(
    int size,
    int hashsize)
{
  assert(size > 128 || size < LRU_MAX);
  assert(hashsize > 128 || hashsize < (LRU_MAX * 2));
  lru_size = size;
  lru_h_size = hashsize;
  lru_t * lru = malloc(sizeof(lru_t));
  if (!lru)
    return NULL;

  pthread_key_create(lru, NULL);
  return lru;
}

/* The caller must ensure that you dont destroy this whilst others
 * are still using it! */
void lru_destroy(
    lru_t *key)
{
  int i;
  for (i=0; i < lru_num; i++) {
    lru_real_destroy(lrus[i]);
  }
  lru_num = 0;
  free(lrus);
  lrus = NULL;
  pthread_key_delete(*key);
  free(key);
}



/* This flushes all the LRUs */
void lru_flush(
    void)
{
  int i;
  for (i=0; i < lru_num; i++)
    lru_real_flush(lrus[i]);
}


uint64_t lru_hits(
    void)
{
  int i;
  uint64_t total=0;
  for (i=0; i < lru_num; i++) {
    total += lrus[i]->hits;
  }
  return total;
}

uint64_t lru_misses(
    void)
{
  int i;
  uint64_t total=0;
  for (i=0; i < lru_num; i++) {
    total += lrus[i]->misses;
  }
  return total;
}



#endif
#undef LRULOCK
#endif
