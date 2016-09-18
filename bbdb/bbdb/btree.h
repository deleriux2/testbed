#ifndef _BLITZ_H
#define _BLITZ_H

#include "config.h"
#include "page.h"
#include "index.h"

/*The internal node representation */
typedef struct btree_in_node_t {
  char mode;
  uint32_t key;
  /* Stores the value from the opposite end of the range */
  uint32_t sibling;
  /* Stores the index to the entries external nodes. Or {0,0} if a leaf. */
  int64_t external_nodes[2];
} btree_in_node_t;

#define TREE_EX_NODE_SIZE 24

#define TREE_NUM_INTERNAL_NODES ((\
  (DATALEN - TREE_EX_NODE_SIZE) \
  / (sizeof(btree_in_node_t)) \
  & 0xFFFFFFFE))


/* The external node representation */
typedef struct btree_ex_node_t {
  /* Parent Offset */
  uint64_t upidx;
  /* The position of the median internal node */
  int32_t offset;
  /* The number of active keys in the index */
  int32_t size;
  /* The keys */
  /* A reserve key is given for child->parent key migration */
  btree_in_node_t keys[TREE_NUM_INTERNAL_NODES+1];
} btree_ex_node_t;

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
  /* The position in file the btree root data lives */
  off_t hdr_offset;
  volatile int64_t hits;
  volatile int64_t misses;
} btree_t;


/* Permits traversal of the tree */
typedef struct btree_traverse {
  btree_t *tree;
  int nodesz;
  uint64_t exstack[512];
  uint32_t innodes[TREE_NUM_INTERNAL_NODES];
} btree_traverse_t;



btree_t * btree_new(pagemap_t *map, index_t *index, off_t hdr_offset);
btree_t * btree_open(pagemap_t *map, index_t *index, off_t hdr_offset);
int btree_insert(btree_t *tree, uint32_t low, uint32_t high);
int btree_verdict(btree_t *tree, uint32_t key);
void btree_close(btree_t *tree);
int btree_delete(btree_t *tree, uint32_t key);
void btree_traverse_init(btree_t *tree, btree_traverse_t *trav);
int btree_traverse_next(btree_traverse_t *trav, uint32_t *low, uint32_t *high);

#endif
