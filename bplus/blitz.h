#ifndef _BTREE_H
#define _BTREE_H

#include "config.h"
#include "page.h"
#include "index.h"

/*The internal node representation */
typedef struct blitz_in_node_t {
  /* The actual key value */
  uint8_t used;
  uint32_t key_low;
  uint32_t key_high;
  /* Stores the index to the entries external nodes. Or {0,0} if a leaf. */
  int64_t external_nodes[2];
} blitz_in_node_t;

#define TREE_EX_NODE_SIZE 16

#define TREE_NUM_INTERNAL_NODES ((\
  (DATALEN - TREE_EX_NODE_SIZE) \
  / (sizeof(blitz_in_node_t)) \
  & 0xFFFFFFFE))

/* The external node representation */
typedef struct blitz_ex_node_t {
  /* Parent Offset */
  uint64_t upidx;
  /* The position of the median internal node */
  int32_t offset;
  /* The number of active keys in the index */
  int32_t size;
  /* The keys */
  /* A reserve key is given for child->parent key migration */
  blitz_in_node_t keys[TREE_NUM_INTERNAL_NODES+1];
} blitz_ex_node_t;

/* The main structure */
typedef struct btree_t {
  pagemap_t *map;
  index_t *index;
  /* Actual size of the database -- in nodes */
  int64_t node_num;
  /* The number of keys stored in the btree */
  int64_t record_num;
  /* The root of the node */
  int64_t offset;
  volatile int64_t hits;
  volatile int64_t misses;
} blitz_t;

/*
btree_t * btree_new(pagemap_t *map, index_t *index);
btree_t * btree_open(pagemap_t *map, index_t *index);
enum verdict btree_insert(btree_t *tree, uint32_t key, enum verdict verdict);
enum verdict btree_verdict(btree_t *tree, uint32_t key);
void btree_close(btree_t *tree);
// print *(btree_ex_node_t *)(tree->map->map + (4096 * 3) + 48)
*/
#endif
