#include "btree.h"
static btree_ex_node_t * btree_external_node_init(btree_t *tree, int64_t upidx);
static btree_in_node_t * btree_find_internal(btree_ex_node_t *ex, int key);
static btree_in_node_t * btree_search_internal(btree_ex_node_t *ex, int key);
static enum verdict btree_insert_internal(btree_ex_node_t *ex, btree_in_node_t *in, uint32_t key, uint32_t sibling, char mode, uint64_t left, uint64_t right);
static enum verdict btree_internal_delete(btree_ex_node_t *ex, btree_in_node_t *in, int64_t index);
static enum verdict merge_left(btree_t *tree, btree_ex_node_t *le, btree_in_node_t *in, btree_ex_node_t *ri);
static enum verdict merge_right(btree_t *tree, btree_ex_node_t *le, btree_in_node_t *in, btree_ex_node_t *ri);
static inline btree_ex_node_t * btree_external_node(btree_t *tree, int64_t offset);
static int btree_external_delete(btree_t *tree, btree_ex_node_t *ex);
static int find_node(btree_t *tree, uint32_t key, btree_ex_node_t **outex, btree_in_node_t **outin);
static int get_left_parent(btree_t *tree, btree_ex_node_t *ex, btree_ex_node_t **outex, btree_in_node_t **outin);
static int get_next(btree_t *tree, btree_in_node_t *inin, btree_ex_node_t **outex, btree_in_node_t **outin);
static int get_prev(btree_t *tree, btree_in_node_t *inin, btree_ex_node_t **outex, btree_in_node_t **outin);
static int get_right_parent(btree_t *tree, btree_ex_node_t *ex, btree_ex_node_t **outex, btree_in_node_t **outin);
static int read_btree_header(btree_t *tree);
static int walk_nodes(btree_t *tree, uint32_t low, uint32_t high, uint32_t **found, int *sz);
static int write_btree_header(btree_t *tree);
static int64_t btree_split(btree_t *tree, btree_ex_node_t *ex, uint32_t key);
static void btree_rebalance(btree_t *tree, btree_ex_node_t *ex);
static void get_left_neighbour(btree_t *tree, btree_ex_node_t *ex, btree_ex_node_t **ne);
static void get_right_neighbour(btree_t *tree, btree_ex_node_t *ex, btree_ex_node_t **ne);
static void left_shift(btree_t *tree, btree_ex_node_t *le, btree_in_node_t *in, btree_ex_node_t *ri);
static void right_shift(btree_t *tree, btree_ex_node_t *le, btree_in_node_t *in, btree_ex_node_t *ri);


static btree_ex_node_t * btree_external_node_init(
    btree_t *tree, 
    int64_t upidx)
{
  assert(tree);
  assert(upidx >= 0);

  /* Initialize page */
  page_t *page;
  btree_ex_node_t *ex;
  int64_t offset;

  page = page_init(tree->map, BBDB_MAGIC_EXNODE);
  if (!page)
    return NULL;

  ex = page_get_data(page);
  offset = page_get_offset(tree->map, page);
  if (index_add(tree->index, page));

  /* Initialize the node */
  ex->upidx = upidx;
  tree->node_num++;
  ex->offset = 0;
  memset(ex->keys, 0, TREE_NUM_INTERNAL_NODES * TREE_EX_NODE_SIZE);
  return ex;
}


static btree_in_node_t * btree_find_internal(
   btree_ex_node_t *ex,
   int key)
{
  assert(ex);

  int first, middle, last;
  btree_in_node_t *in = NULL;
  first = 0;
  last = ex->size-1;
  middle = ex->size/2;

  if (ex->size <= 0)
    return &ex->keys[0];

  while (first <= last) {
    in = &ex->keys[middle];

    if (key == in->key && key && in-ex->keys < ex->size)
      return in;

    if (key > in->key)
      first = middle+1;  
    else
      last = middle - 1;

    middle = (first + last) / 2;
  }

  if (in > &ex->keys[ex->size])
    in = &ex->keys[ex->size-1];
  else if (in < ex->keys)
    in = &ex->keys[0];

  return in;
}


static btree_in_node_t * btree_search_internal(
   btree_ex_node_t *ex,
   int key)
{
  assert(ex);

  int first, middle, last;
  btree_in_node_t *in = NULL;
  first = 0;
  last = ex->size-1;
  middle = ex->size/2;

  if (ex->size <= 0)
    return &ex->keys[0];

  while (first <= last) {
    in = &ex->keys[middle];

    if (
        (in->mode == OPEN && key >= in->key && key < 
         in->sibling && (in-ex->keys < ex->size))
        ||
        (in->mode == CLOSE && key < in->key && key >=
         in->sibling && (in-ex->keys < ex->size)))
      return in;

    if (key > in->key)
      first = middle+1;  
    else
      last = middle - 1;

    middle = (first + last) / 2;
  }

  if (in > &ex->keys[ex->size])
    in = &ex->keys[ex->size-1];
  else if (in < ex->keys)
    in = &ex->keys[0];

  return in;
}


static enum verdict btree_insert_internal(
    btree_ex_node_t *ex,
    btree_in_node_t *in,
    uint32_t key,
    uint32_t sibling,
    char mode,
    uint64_t left,
    uint64_t right)
{
  assert(ex);
  assert(in);

  /* Our relative position in the index */
  int idx = in - ex->keys;

  /* Case 1: Going into an empty node */
  if (ex->size == 0) {
    in->key = key;
    in->sibling = sibling;
    in->mode = mode;
    in->external_nodes[0] = left;
    in->external_nodes[1] = right;
    ex->size++;
    return NONE;
  }
  /* Case 2: Existing smaller than new key
   * Move once to the right, shift all values by right one. */
  else if (key >= in->key)
    in++;
  memmove((in+1), in, (ex->size-idx) * sizeof(*in));
  ex->size++;
  ex->offset = ex->size / 2;
  in->key = key;
  in->sibling = sibling;
  in->mode = mode;
  in->external_nodes[0] = left;
  in->external_nodes[1] = right;

  if (ex->size >= TREE_NUM_INTERNAL_NODES)
    return SPLIT;
  else
    return NONE;
}


static enum verdict btree_internal_delete(
    btree_ex_node_t *ex,
    btree_in_node_t *in,
    int64_t index) /* this is the index that the neighbouring nodes should point to */
{
  assert(ex);
  assert(in);

  int64_t offset = in - ex->keys;
  int64_t diff = (ex->size-1) - offset;
  btree_in_node_t *inl = NULL;
  btree_in_node_t *inr = NULL;

  if (ex->size == 0)
    return ERROR;

  if (offset < 0 || offset > ex->size)
    return ERROR;

  if (offset > 0)
    inl = in-1;
  if (offset < (ex->size-1))
    inr = in+1;

  /* Update the neighbouring nodes to use the correct index */
  if (inl)
    inl->external_nodes[1] = index;
  if (inr)
    inr->external_nodes[0] = index;

  /* Reduce external nodes size by one */
  ex->size--;
  /* Copy all the nodes offset+1 away from this one to offset */
  if (offset < ex->size)
    memmove(in, in+1, diff * sizeof(btree_in_node_t));
  /* Wipe the end node */
  memset(&ex->keys[ex->size], 0, sizeof(btree_in_node_t));

  /* If the size is now zero, this indicates we can delete the node,
     this will ONLY ever occur on a root node */
  if (ex->size == 0) {
    assert(ex->upidx == 0);
    return DELETE;
  }
  /* If this external node is root, we never need to signal
      for a rebalance.
   */
  if (ex->upidx == 0)
    return DEFAULT;

  /* If the size of the node is less than half, signal a rebalance */
  if (ex->size < (TREE_NUM_INTERNAL_NODES/2)-1)
    return REBALANCE;

  return DEFAULT;
}


static enum verdict merge_left(
    btree_t *tree,
    btree_ex_node_t *le,
    btree_in_node_t *in,
    btree_ex_node_t *ri)
{
  assert(le);
  assert(in);
  assert(ri);

  btree_in_node_t tmpkeys[TREE_NUM_INTERNAL_NODES+1];
  btree_ex_node_t *ex, *up;
  int totalsz = le->size + 1 + ri->size;
  int i;
  int index = page_get_index_of(le);
  int offset;

  memset(tmpkeys, 0, sizeof(btree_in_node_t) * TREE_NUM_INTERNAL_NODES + 1);

  /* There should be enough room in the left hand node
   * for this to fit */
  assert(le->size + 1 + ri->size < TREE_NUM_INTERNAL_NODES);

  /* Copy all the nodes from the left hand node */
  memcpy(&tmpkeys[0], &le->keys[0], le->size * sizeof(btree_in_node_t));
  /* Add the parent node */
  memcpy(&tmpkeys[le->size], in, sizeof(btree_in_node_t));
  /* Copy all the keys from the right hand node */
  memcpy(&tmpkeys[le->size+1], &ri->keys[0], 
                      ri->size * sizeof(btree_in_node_t));
  /* Modify the parents node linkages to reflect new left and right */
  tmpkeys[le->size].external_nodes[0] = tmpkeys[le->size-1].external_nodes[1];
  tmpkeys[le->size].external_nodes[1] = tmpkeys[le->size+1].external_nodes[0];
  /* Delete the old external node */
  btree_external_delete(tree, ri);

  /* Update all the child nodes of these nodes to point to
   * to correct up index */
  for (i=0; i < totalsz; i++) {
    offset = tmpkeys[i].external_nodes[0];
    if (offset == 0)
      break;
    ex = btree_external_node(tree, offset);
    ex->upidx = index;

    offset = tmpkeys[i].external_nodes[1];
    if (offset == 0)
      break;
    ex = btree_external_node(tree, offset);
    ex->upidx = index;
  }

  /* Overwrite the nodes on the left with the new keys */
  memcpy(le->keys, tmpkeys, totalsz * sizeof(btree_in_node_t));
  /* Correct the lefts sizes and offests */
  le->size = totalsz;
  le->offset = totalsz/2;

  /* Delete the parent node */
  up = btree_external_node(tree, le->upidx);
  return btree_internal_delete(up, in, index);
}


static enum verdict merge_right(
    btree_t *tree,
    btree_ex_node_t *le,
    btree_in_node_t *in,
    btree_ex_node_t *ri)
{
  assert(le);
  assert(in);
  assert(ri);

  btree_in_node_t tmpkeys[TREE_NUM_INTERNAL_NODES+1];
  btree_ex_node_t *ex, *up;
  int totalsz = le->size + 1 + ri->size;
  int i;
  int index = page_get_index_of(ri);
  int offset;

  /* There should be enough room in the right hand node
   * for this to fit */
  assert(le->size + 1 + ri->size < TREE_NUM_INTERNAL_NODES);

  /* Copy all the nodes from the left hand node */
  memcpy(&tmpkeys[0], &le->keys[0], le->size * sizeof(btree_in_node_t));
  /* Add the parent node */
  memcpy(&tmpkeys[le->size], in, sizeof(btree_in_node_t));
  /* Copy all the keys from the right hand node */
  memcpy(&tmpkeys[le->size+1], &ri->keys[0], 
                      ri->size * sizeof(btree_in_node_t));
  /* Modify the parents node linkages to reflect new left and right */
  tmpkeys[le->size].external_nodes[0] = tmpkeys[le->size-1].external_nodes[1];
  tmpkeys[le->size].external_nodes[1] = tmpkeys[le->size+1].external_nodes[0];
  /* Delete the old external node */
  btree_external_delete(tree, le);

  /* Update all the child nodes of these nodes to point to
   * to correct up index */
  for (i=0; i < totalsz; i++) {
    offset = tmpkeys[i].external_nodes[0];
    if (offset == 0)
      break;
    ex = btree_external_node(tree, offset);
    ex->upidx = index;

    offset = tmpkeys[i].external_nodes[1];
    if (offset == 0)
      break;
    ex = btree_external_node(tree, offset);
    ex->upidx = index;
  }

  /* Overwrite the nodes on the right with the new keys */
  memcpy(ri->keys, tmpkeys, totalsz * sizeof(btree_in_node_t));
  /* Correct the rights sizes and offests */
  ri->size = totalsz;
  ri->offset = totalsz/2;

  /* Delete the parent node */
  up = btree_external_node(tree, ri->upidx);
  return btree_internal_delete(up, in, index);
}


static inline btree_ex_node_t * btree_external_node(
    btree_t *tree,
    int64_t offset)
{
  assert(tree);
  assert(offset >= 0);
  btree_ex_node_t *ex;

  int64_t pageno; 

  pageno = index_lookup(tree->index, offset);
  if (!index_lookup)
    return NULL;

  ex = page_get_data_of(tree->map, pageno, BBDB_MAGIC_EXNODE);

  assert(ex);
  return ex;
}

static inline btree_in_node_t * btree_internal(
   btree_ex_node_t *ex,
   int offset)
{
  assert(ex);
  assert(offset >= 0 && offset < TREE_NUM_INTERNAL_NODES);
  return &ex->keys[offset];
}


static int btree_external_delete(
    btree_t *tree,
    btree_ex_node_t *ex)
{
  assert(tree);
  assert(ex);

  int64_t index;
  int64_t offset;
  page_t *page;

  index = page_get_index_of(ex);
  offset = index_lookup(tree->index, index);
  page = page_get(tree->map, offset);

  if (!page)
    return 0;

  if (!index_delete(tree->index, page))
    return 0;

  page_wipe(page);

  /* Reduce sizes down as appopriate */
  tree->node_num--;
  if (tree->node_num == 0)
    tree->offset = 0;

  return 1;
}


static int find_node( 
    btree_t *tree, 
    uint32_t key,
    btree_ex_node_t **outex,
    btree_in_node_t **outin) 
{ 
  assert(tree);
 
  int pos; 
  btree_ex_node_t *ex = NULL;
  btree_in_node_t *in = NULL; 
  uint64_t idx; 
  
  ex = btree_external_node(tree, tree->offset);
  /* No match if there is no tree */
  if (!ex) 
    return 0;

  while (1) {
    in = btree_find_internal(ex, key); 
    /* Check if it was the key, or just the closest match */ 
    if (in->key != key) { 
      pos = key > in->key ? 1 : 0; 
      /* If a external node exists, descend. */ 
      if (in->external_nodes[pos] == 0) {
        *outex = ex;
        *outin = in;
        return 0;
      }
      ex = btree_external_node(tree, in->external_nodes[pos]); 
      continue; 
    } 
    /* Key does not exist */ 
    else if (in->mode == NONE)  {
      *outex = ex;
      *outin = in;
      return 0; 
    }
    /* Key matched */ 
    else { 
      *outex = ex;
      *outin = in;
      return 1; 
    } 
  } 
}


static int get_left_parent(
    btree_t *tree,
    btree_ex_node_t *ex,
    btree_ex_node_t **outex,
    btree_in_node_t **outin)
{
  assert(ex);
  int i;
  btree_ex_node_t *up;
  btree_in_node_t *in;
  int index;

  if (ex->upidx == 0)
    return 0;

  index = page_get_index_of(ex);

  up = btree_external_node(tree, ex->upidx);
  assert(up);
  /* Scan the node looking for the internal node which contains
     a parent attached to the left of this node
   */
  for (i=0; i < up->size; i++) {
    in = &up->keys[i];
    if (in->external_nodes[0] == index) {
      *outex = up;
      *outin = in;
      return 1;
    }
  }
  return 0;
}


static int get_next(
    btree_t *tree,
    btree_in_node_t *inin,
    btree_ex_node_t **outex,
    btree_in_node_t **outin)
{
  assert(inin);
  assert(outex);
  assert(outin);

  btree_ex_node_t *ex;
  btree_in_node_t *in;

  /* Successors go right -> left * n -> leaf
     Predecessors go left -> right * n -> leaf
   */

  /* If already a leaf */
  if (inin->external_nodes[1] == 0)
    return 0;

  /* Go the next node down */
  ex = btree_external_node(tree, inin->external_nodes[1]);
  assert(ex);
  in = &ex->keys[0];

  /* Iterate down the left hand side until you reach a leaf */
  while (in->external_nodes[0] != 0) {
    ex = btree_external_node(tree, in->external_nodes[0]);
    assert(ex);
    in = &ex->keys[0];
  }

  *outin = in;
  *outex = ex;
  return 1;
}


static int get_prev(
    btree_t *tree,
    btree_in_node_t *inin,
    btree_ex_node_t **outex,
    btree_in_node_t **outin)
{
  assert(inin);
  assert(outex);
  assert(outin);

  btree_ex_node_t *ex;
  btree_in_node_t *in;

  /* Successors go right -> left * n -> leaf
     Predecessors go left -> right * n -> leaf
   */

  /* If already a leaf */
  if (inin->external_nodes[0] == 0) {
    *outex = NULL;
    *outin = NULL;
    return 0;
  }

  /* Go the next node down */
  ex = btree_external_node(tree, inin->external_nodes[0]);
  assert(ex);
  in = &ex->keys[(ex->size-1)];

  /* Iterate down the left hand side until you reach a leaf */
  while (in->external_nodes[(ex->size-1)] != 0) {
    ex = btree_external_node(tree, in->external_nodes[(ex->size-1)]);
    assert(ex);
    in = &ex->keys[0];
  }

  *outin = in;
  *outex = ex;
  return 1;
}


static int get_right_parent(
    btree_t *tree,
    btree_ex_node_t *ex,
    btree_ex_node_t **outex,
    btree_in_node_t **outin)
{
  assert(ex);
  int i;
  btree_ex_node_t *up;
  btree_in_node_t *in;
  int index;

  if (ex->upidx == 0)
    return -1;

  index = page_get_index_of(ex);

  up = btree_external_node(tree, ex->upidx);
  assert(up);
  /* Scan the node looking for the internal node which contains
     a parent attached to the right of this node
   */
  for (i=0; i < up->size; i++) {
    in = &up->keys[i];
    if (in->external_nodes[1] == index) {
      *outex = up;
      *outin = in;
      return 1;
    }
  }
  return 0;
}


static int read_btree_header(
    btree_t *tree)
{
  assert(tree);
  assert(tree->map);

  struct iovec vecs[3];
  int64_t pageno;
  int64_t records;
  int64_t nodes;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);
  vecs[1].iov_base = &records;
  vecs[1].iov_len = sizeof(records);
  vecs[2].iov_base = &nodes;
  vecs[2].iov_len = sizeof(nodes);

  if (preadv(tree->map->fd, vecs, 3, tree->hdr_offset) < 0)
    return 0;

  tree->offset = pageno;
  tree->record_num = records;
  tree->node_num = nodes;
  
  return 1;
}


static int walk_nodes(
    btree_t *tree,
    uint32_t low,
    uint32_t high,
    uint32_t **found,
    int *sz)
{
  assert(tree);
  btree_ex_node_t *exnodes[512];
  int32_t innodes[512];
  btree_in_node_t *in;
  btree_ex_node_t *ex;
  int nodesz = -1;
  int off;
  int pos;
  uint32_t *fetched = NULL;
  int len = 0;
  int total = 1024;

  fetched = calloc(sizeof(uint32_t), total);
  if (!fetched)
    return -1;

  nodesz++;
  ex = btree_external_node(tree, tree->offset);
  in = btree_find_internal(ex, low);
  innodes[nodesz] = in-ex->keys;
  exnodes[nodesz] = ex;

  pos = low > in->key;
  while (low != in->key && in->external_nodes[pos] != 0) {
    nodesz++;
    ex = btree_external_node(tree, in->external_nodes[pos]);
    in = btree_find_internal(ex, low);
    exnodes[nodesz] = ex;
    innodes[nodesz] = in-ex->keys;
    pos = low > in->key;
  }

  while (nodesz >= 0) {
    off = innodes[nodesz];
    ex = exnodes[nodesz];
    in = &ex->keys[off];
    /* Visit node */
    if (off < ex->size && in->key > low && in->key < high) {
      if (len == total) {
        total += 1024;
        fetched = realloc(fetched, total * sizeof(uint32_t));
      }
      fetched[len++] = in->key;
    }
    if (in->key >= high)
      break;

    /* If theres a right node, go right */
    if (off < ex->size) {
      innodes[nodesz] = ++off;
      in++;
      /* Traverse to the bottom left */
      while (in->external_nodes[0] != 0) {
        nodesz++;
        ex = btree_external_node(tree, in->external_nodes[0]);
        in = &ex->keys[0];
        exnodes[nodesz] = ex;
        innodes[nodesz] = 0;
      }
    }
    /* If we passed the last node */
    else if (off == ex->size) {
      in--;
      innodes[nodesz] = ++off;
      /* Go right one, then traverse all the way left */
      if (in->external_nodes[1] != 0) {
        nodesz++;
        ex = btree_external_node(tree, in->external_nodes[1]);
        in = &ex->keys[0];
        exnodes[nodesz] = ex;
        innodes[nodesz] = 0;
      
        while (in->external_nodes[0] != 0) {
          nodesz++;
          ex = btree_external_node(tree, in->external_nodes[0]);
          in = &ex->keys[0];
          exnodes[nodesz] = ex;
          innodes[nodesz] = 0;
        }
      }
    }
    else {
      nodesz--;
    }
  }

  if (len == 0) {
    free(fetched);
    fetched = NULL;
  }
  *sz = len;
  *found = fetched;
  return len;
}


static int write_btree_header(
    btree_t *tree)
{
  assert(tree);
  assert(tree->map);
  assert(tree->offset >= 0);

  struct iovec vecs[3];

  int64_t pageno = tree->offset;
  int64_t records = tree->record_num;
  int64_t nodes = tree->node_num;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);
  vecs[1].iov_base = &records;
  vecs[1].iov_len = sizeof(records);
  vecs[2].iov_base = &nodes;
  vecs[2].iov_len = sizeof(nodes);

  if (pwritev(tree->map->fd, vecs, 3, tree->hdr_offset) < 0)
    return 0;

  return 1;
}


static int64_t btree_split(
    btree_t *tree,
    btree_ex_node_t *ex,
    uint32_t key)
{
  /* WARNING: On a split theres a chance we re-chunk which remaps the 
     pagemaps mmapped mapping of the database to a new virtual address!
     Because of this we must take care to relocate our external nodes if
     we initialize a new node!
   */

   assert(tree);
   assert(ex);

   int i;
   int oldsize = ex->size;
   int64_t ex_pos;
   btree_in_node_t *in = NULL;
   btree_in_node_t tmp, tmp2;
   btree_ex_node_t *newex = NULL;
   int64_t newex_pos;
   btree_ex_node_t *ex2 = NULL;
   int64_t ex2_pos;
   btree_ex_node_t *up = NULL;
   int64_t up_pos;
   btree_ex_node_t *upup = NULL;
   int64_t upup_pos;
   btree_in_node_t keys[TREE_NUM_INTERNAL_NODES/2];

   ex_pos = page_get_index_of(ex);

   memset(keys, 0, (TREE_NUM_INTERNAL_NODES/2) * sizeof(btree_in_node_t));
  /* 1. Take the median internal node. */
   in = btree_internal(ex, ex->offset);
   memcpy(&tmp, in, sizeof(tmp));

   /* 2. Create a new external node */
   newex = btree_external_node_init(tree, 0);
   newex_pos = page_get_index_of(newex);
   ex = btree_external_node(tree, ex_pos);
   assert(ex);

   /* 3. Copy all the internal nodes to the left of this node into the new 
         external node. Keeping in median placement.
    */
   memcpy(newex->keys, ex->keys, (ex->offset) * sizeof(btree_in_node_t));
   newex->size = ex->offset;
   newex->offset = (ex->offset)/2;

   /* 4. Clear the left nodes from the given external node. Shift the whole 
         list of nodes appropriately to the left, remove the first node 
    */
   memcpy(keys, &ex->keys[ex->offset+1], 
         (ex->offset-1) * sizeof(btree_in_node_t));
   memset(ex->keys, 0, TREE_NUM_INTERNAL_NODES * sizeof(btree_in_node_t));
   memcpy(ex->keys, keys, (ex->offset-1) * sizeof(btree_in_node_t));
   ex->size = ex->offset-1;
   ex->offset = ex->size/2;

   /* 5. Insert the median internal node into the parent external node of
    *    the provided external node. */
   if (ex->upidx == 0) {
      /* Special case: Make a new node, insert median into it, remark this
       * as parent to the new root. */
      up = btree_external_node_init(tree, 0);
      up_pos = page_get_index_of(up);
      ex = btree_external_node(tree, ex_pos);
      newex = btree_external_node(tree, newex_pos);

      assert(ex);
      assert(newex);

      in = btree_internal(up, up->offset);
      ex->upidx = up_pos;
      newex->upidx = up_pos;
      /* Given this should never fail, bail if we dont get this to work */
      if (btree_insert_internal(up, in, tmp.key, tmp.sibling, tmp.mode,
                                         newex_pos, ex_pos) != NONE) {
        ERRX(EXIT_FAILURE, "Something horrific happened");
      }
      tree->offset = up_pos;

     /* The internal node to the left of the new median should point to
        the new node on the right.
     */
     in = btree_find_internal(up, tmp.key);
     if (in != up->keys) {
       in--;
       in->external_nodes[1] = newex_pos;
     }

   }
   else {
     up = btree_external_node(tree, ex->upidx);
     up_pos = page_get_index_of(up);
     assert(up);

     in = btree_find_internal(up, tmp.key);
     ex->upidx = up_pos;
     newex->upidx = up_pos;

     /* If the parent is full, recurse up a branch. */
     if (btree_insert_internal(up, in, tmp.key, tmp.sibling, tmp.mode,
                                             newex_pos, ex_pos) == SPLIT) {

       /* The internal node to the left of the new median should point
          to the new node on the right.
       */
       in = btree_find_internal(up, tmp.key);
       if (in != up->keys) {
         in--;
         in->external_nodes[1] = newex_pos;
       }
       up_pos = btree_split(tree, up, tmp.key);
       up = btree_external_node(tree, up_pos);
       newex = btree_external_node(tree, newex_pos);
       ex = btree_external_node(tree, ex_pos);

       assert(up);
       assert(ex);
       assert(newex);
     }
     else {

       in = btree_find_internal(up, tmp.key);
       if (in != up->keys) {
         in--;
         in->external_nodes[1] = newex_pos;
       }
     }
   }

   /* Iterate over the new external nodes child nodes, setting the correct 
      upidx for each child 
    */
   for (i = 0; i < newex->size; i++) {
     in = btree_internal(newex, i);
     if (in->external_nodes[0] == 0)
       /* All internals must be empty too in this situation */
       break;
     
     ex2 = btree_external_node(tree, in->external_nodes[0]);
     ex2->upidx = newex_pos;
     ex2 = btree_external_node(tree, in->external_nodes[1]);
     ex2->upidx = newex_pos;
   }

   /* Using the key provided by the input, now rescan the parent and find the
      closest matching node, this is used for recursion
    */
   in = btree_find_internal(up, key);
   return in->external_nodes[key > in->key];
}


static void btree_rebalance(
    btree_t *tree,
    btree_ex_node_t *ex)
{
  assert(tree);
  assert(ex);

  enum verdict verdict;
  btree_ex_node_t *le = NULL;
  btree_ex_node_t *ri = NULL;
  btree_ex_node_t *up = NULL;
  btree_in_node_t *inupl = NULL;
  btree_in_node_t *inupr = NULL;

  get_right_parent(tree, ex, &up, &inupr);
  get_left_parent(tree, ex, &up, &inupl);

  /* We must be the root node, theres no parent */
  if (!up)
    return;
  assert(inupl || inupr);

  get_left_neighbour(tree, ex, &le);
  get_right_neighbour(tree, ex, &ri);

  assert(le || ri);

  /* Start by attempting to ascertain if we can shift a node right
     from our left neighbour */
  if (le && (le->size-1) >= (TREE_NUM_INTERNAL_NODES/2)-1) {
    right_shift(tree, le, inupr, ex);
    return;
  }
  /* Try seeing if we can shift a node left from our right
     neighbour */
  else if (ri && (ri->size-1) >= (TREE_NUM_INTERNAL_NODES/2)-1) {
    left_shift(tree, ex, inupl, ri);
    return;
  }
  /* Determine if we can merge our left node to our right node */
  else if (le) {
    verdict = merge_right(tree, le, inupr, ex);
  }
  else if (ri) {
    verdict = merge_left(tree, ex, inupl, ri);
  }
  else {
    assert(1==0);
  }

  if (verdict == REBALANCE) {
    btree_rebalance(tree, up);
  }
  /* In the case of an empty root node delete and reparent */
  else if (verdict == DELETE) {
    btree_external_delete(tree, up);
    tree->offset = page_get_index_of(ex); 
    ex->upidx = 0;
  }
}


static void get_left_neighbour(
    btree_t *tree,
    btree_ex_node_t *ex,
    btree_ex_node_t **ne)
{
  assert(tree);
  assert(ex);
  assert(ne);

  btree_ex_node_t *up;
  btree_ex_node_t *re;
  btree_in_node_t *in;

  /* There is no right parent, indicating we are the leftest node */
  if (!get_right_parent(tree, ex, &up, &in))
    return;

  re = btree_external_node(tree, in->external_nodes[0]);
  assert(re);

  *ne = re;
  return;
}

static void get_right_neighbour(
    btree_t *tree,
    btree_ex_node_t *ex,
    btree_ex_node_t **ne)
{
  assert(tree);
  assert(ex);
  assert(ne);

  btree_ex_node_t *up;
  btree_ex_node_t *re;
  btree_in_node_t *in;

  /* There is no left parent, indicating we are the rightest node */
  if (!get_left_parent(tree, ex, &up, &in))
    return;

  re = btree_external_node(tree, in->external_nodes[1]);
  assert(re);

  *ne = re;
  return;
}


static void left_shift(
    btree_t *tree,
    btree_ex_node_t *le,
    btree_in_node_t *in,
    btree_ex_node_t *ri)
{
  assert(le);
  assert(in);
  assert(ri);

  btree_ex_node_t *chld;
  btree_in_node_t tmpend;
  btree_in_node_t tmpup;
  btree_in_node_t tmpst;
  int lindex = page_get_index_of(le);

  /* Check there is enough space in the right hand
     to permit this operation and on the left not
     to break balance */
  assert((ri->size-1) >= (TREE_NUM_INTERNAL_NODES/2)-1);
  assert((le->size+1) < (TREE_NUM_INTERNAL_NODES));

  /* Copy the start node from the right */
  memcpy(&tmpst, &ri->keys[0], sizeof(btree_in_node_t));
  /* Copy the end node from the left */
  memcpy(&tmpend, &le->keys[le->size-1], sizeof(btree_in_node_t));
  /* Copy the up node from the parent */
  memcpy(&tmpup, in, sizeof(btree_in_node_t));

  /* Delete the start key from the right hand side */
  btree_internal_delete(ri, &ri->keys[0], tmpst.external_nodes[1]);
  /* Copy the key value from start into up */
  in->key = tmpst.key;
  in->sibling = tmpst.sibling;
  in->mode = tmpst.mode;
  /* Insert old parent to the left */
  btree_insert_internal(le, &le->keys[le->size-1], tmpup.key, 
                        tmpup.sibling, tmpup.mode,
                        tmpend.external_nodes[1], 
                        tmpst.external_nodes[0]);

  /* Fix the upindex of the external node you just moved */
  if (tmpst.external_nodes[0]) {
    chld = btree_external_node(tree, tmpst.external_nodes[0]);
    assert(chld);
    chld->upidx = lindex;
  }
}


static void right_shift(
    btree_t *tree,
    btree_ex_node_t *le,
    btree_in_node_t *in,
    btree_ex_node_t *ri)
{
  assert(le);
  assert(in);
  assert(ri);

  btree_ex_node_t *chld;
  btree_in_node_t tmpend;
  btree_in_node_t tmpup;
  btree_in_node_t tmpst;
  int rindex = page_get_index_of(ri);
  /* Check there is enough space in the right hand
     to permit this operation and on the left not
     to break balance */
  assert((ri->size+1) < TREE_NUM_INTERNAL_NODES);
  assert((le->size-1) >= (TREE_NUM_INTERNAL_NODES/2)-1);

  /* Copy the start node from the right */
  memcpy(&tmpst, &ri->keys[0], sizeof(btree_in_node_t));
  /* Copy the end node from the left */
  memcpy(&tmpend, &le->keys[le->size-1], sizeof(btree_in_node_t));
  /* Copy the up node from the parent */
  memcpy(&tmpup, in, sizeof(btree_in_node_t));

  /* Delete the end key from the left hand side */
  btree_internal_delete(le, &le->keys[le->size-1], tmpend.external_nodes[0]);
  /* Copy the key value from end into up */
  in->key = tmpend.key;
  in->sibling = tmpend.sibling;
  in->mode = tmpend.mode;
  /* Insert old parent to the right */
  btree_insert_internal(ri, &ri->keys[0], tmpup.key, 
                        tmpup.sibling, tmpup.mode, 
                        tmpend.external_nodes[1], 
                        tmpst.external_nodes[0]);

  /* Fix the upindex of the external node you just moved */
  if (tmpend.external_nodes[1]) {
    chld = btree_external_node(tree, tmpend.external_nodes[1]);
    assert(chld);
    chld->upidx = rindex;
  }
}




void btree_traverse_init(
    btree_t *tree,
    btree_traverse_t *trav)
{
  assert(tree);

  btree_ex_node_t *ex;
  btree_in_node_t *in;

  trav->tree = tree;
  trav->nodesz = -1;
  memset(trav->exstack, 0, sizeof(trav->exstack));
  memset(trav->innodes, 0, sizeof(trav->innodes));

  /* There is no tree */
  if (tree->offset == 0)
    return;

  /* Prep the stack by doing the initial left walk */
  trav->nodesz++;
  ex = btree_external_node(trav->tree, trav->tree->offset);
  in = btree_find_internal(ex, 0);
  trav->innodes[trav->nodesz] = 0;
  trav->exstack[trav->nodesz] = page_get_index_of(ex);

  while (in->external_nodes[0] != 0) {
    trav->nodesz++;
    ex = btree_external_node(trav->tree, in->external_nodes[0]);
    in = &ex->keys[0];
    trav->innodes[trav->nodesz] = 0;
    trav->exstack[trav->nodesz] = page_get_index_of(ex);    
  }
  return;
}




int btree_traverse_next(
    btree_traverse_t *trav,
    uint32_t *low,
    uint32_t *high)
{
  assert(trav);

  btree_in_node_t *in;
  btree_ex_node_t *ex;
  int off;
  bool open;

  /* This goto is here because we store the nodes twice,
     so we skip over close nodes */
retry:
  open = false;

  if (trav->nodesz >= 0) {
    off = trav->innodes[trav->nodesz];
    ex = btree_external_node(trav->tree, trav->exstack[trav->nodesz]);
    in = &ex->keys[off];
    /* Visit node */
    if (off < ex->size) {
      if (in->mode == OPEN) {
        open = true;
        *low = in->key;
        *high = in->sibling;
      }
    }

    /* If theres a right node, go right */
    if (off < ex->size) {
      trav->innodes[trav->nodesz] = ++off;
      in++;
      /* Traverse to the bottom left */
      while (in->external_nodes[0] != 0) {
        trav->nodesz++;
        ex = btree_external_node(trav->tree, in->external_nodes[0]);
        in = &ex->keys[0];
        trav->exstack[trav->nodesz] = page_get_index_of(ex);
        trav->innodes[trav->nodesz] = 0;
      }
    }
    /* If we passed the last node */
    else if (off == ex->size) {
      in--;
      trav->innodes[trav->nodesz] = ++off;
      /* Go right one, then traverse all the way left */
      if (in->external_nodes[1] != 0) {
        trav->nodesz++;
        ex = btree_external_node(trav->tree, in->external_nodes[1]);
        in = &ex->keys[0];
        trav->exstack[trav->nodesz] = page_get_index_of(ex);
        trav->innodes[trav->nodesz] = 0;
      
        while (in->external_nodes[0] != 0) {
          trav->nodesz++;
          ex = btree_external_node(trav->tree, in->external_nodes[0]);
          in = &ex->keys[0];
          trav->exstack[trav->nodesz] = page_get_index_of(ex);
          trav->innodes[trav->nodesz] = 0;
        }
      }
    }
    else {
      trav->nodesz--;
    }
  }
  else {
    return 0;
  }

  if (!open)
    goto retry;
  return 1;
}



/* Inserts an entry into the btree */
int btree_insert(
    btree_t *tree,
    uint32_t low,
    uint32_t high)
{
  assert(tree);

  uint32_t ohigh = high;
  uint32_t olow = low;
  int pos;
  int mode;
  enum verdict v;
  uint32_t *found = NULL;
  int sz, i;
  btree_ex_node_t *le = NULL;
  btree_in_node_t *li = NULL;
  btree_ex_node_t *he = NULL;
  btree_in_node_t *hi = NULL;
  btree_ex_node_t *ex = NULL;
  btree_in_node_t *in = NULL;

  if (low >= high)
    return -1;

  /* Brand new tree */
  if (tree->offset == 0) {
    le = btree_external_node_init(tree, 0);
    tree->offset = page_get_index_of(le);
  }

  /* Start by looking for the lowest match */
  find_node(tree, low, &le, &li);
  /* Nothing at all came back. So insert a new node. */
  if (li->mode == NONE) {
    v = btree_insert_internal(le, li, low, high, OPEN, 0, 0);
  }
  else if (low > li->key) {
    if (li->mode == CLOSE) {
      /* Insert the new range */
      v = btree_insert_internal(le, li, low, high, OPEN, 0, 0);
    }
    else {
      low = li->key;
      li->mode = OPEN;
    }
  }
  else {
    if (li->mode == CLOSE) {
      find_node(tree, li->sibling, &ex, &in);
      le = ex; ex = NULL;
      li = in; in = NULL;
      low = li->key;
      li->mode = OPEN;
    }
    else {
      /* Alter the range start of existing key */
      if (high < li->key) {
        v = btree_insert_internal(le, li, low, high, OPEN, 0, 0);
      }
      else {
        li->key = low;
      }
    }
  }
  if (v == SPLIT)
    btree_split(tree, le, le->keys[le->offset].key);

  v = NONE;
  find_node(tree, low, &le, &li);
  find_node(tree, high, &he, &hi);
  if (li == hi)
    find_node(tree, li->sibling, &he, &hi);

  if (high >= hi->key) {
    if (hi->mode == OPEN) {
      /* Fetch the location of its close companion */
      find_node(tree, hi->sibling, &ex, &in);
      assert(ex);
      if (li == hi) {
        v = btree_insert_internal(he, hi, high, low, CLOSE, 0, 0);
      }
      else {
        he = ex; ex = NULL;
        hi = in; in = NULL;
        high = hi->key;
        hi->mode = CLOSE;
      }
    }
    else {
      /* Alter the range end of existing key */
      if (low > hi->key) {
        v = btree_insert_internal(he, hi, high, low, CLOSE, 0, 0);
      }
      else {
        hi->key = high;
      }
    }
  }
  else {
    if (hi->mode == OPEN) {
      /* Insert the new range */
      v = btree_insert_internal(he, hi, high, low, CLOSE, 0, 0);
    }
    else {
      high = hi->key;
    }
  }

squish:
  if (v == SPLIT) 
    btree_split(tree, he, he->keys[le->offset].key);

  find_node(tree, high, &he, &hi);
  find_node(tree, low, &le, &li);

  /* Modify each sibling */
  assert(low <= olow);
  assert(high >= ohigh);
  if (li->sibling != 0 && high < li->sibling)
    assert(1 == 0);
  if (hi->sibling != 0 && low > hi->sibling)
    assert(1 == 0);
  li->sibling = high;
  hi->sibling = low;

  /* Begin the deletion walk */
  walk_nodes(tree, low, high, &found, &sz);
  for (i=0; i < sz; i++) 
    btree_delete(tree, found[i]);

  if (found)
    free(found);
  return 1;
}




/* Create a new btree */
btree_t * btree_new(
    pagemap_t *map,
    index_t *index,
    off_t hdr_offset)
{
  assert(map);
  assert(index);

  btree_t *tree;
  tree = malloc(sizeof(btree_t));
  if (!tree)
    goto fail;

  tree->map = map;
  tree->index = index;
  tree->node_num = 0;
  tree->record_num = 0;
  tree->offset = 0;
  tree->hdr_offset = hdr_offset;
  tree->hits = 0;
  tree->misses = 0;

  if (!write_btree_header(tree))
    goto fail;

  return tree;

fail:
  if (tree)
    free(tree);
  return NULL;
}



/* Opens an existing btree */
btree_t * btree_open(
    pagemap_t *map,
    index_t *index,
    off_t hdr_offset)
{
  assert(map);
  assert(index);

  btree_t *tree;
  tree = malloc(sizeof(btree_t));
  if (!tree)
    goto fail;

  tree->map = map;
  tree->index = index;
  tree->node_num = 0;
  tree->record_num = 0;
  tree->offset = 0;
  tree->hdr_offset = hdr_offset;
  tree->hits = 0;
  tree->misses = 0;

  if (!read_btree_header(tree))
    goto fail;

  return tree;

fail:
  if (tree)
    free(tree);
  return NULL;
}



/* Returns a verdict for a key in the btree */
int btree_verdict( 
    btree_t *tree, 
    uint32_t candidate) 
{ 
  assert(tree);
 
  int pos; 
  btree_ex_node_t *ex = NULL;
  btree_in_node_t *in = NULL; 
  uint64_t idx; 
  enum verdict v; 

  if (tree->offset == 0) {
    return 0;
  }
  ex = btree_external_node(tree, tree->offset);
  /* No match if there is no tree */
  if (!ex) {
    ATOMIC_INC(tree->misses);
    return 0;
  }

  while (1) { 
    in = btree_search_internal(ex, candidate); 
    /* Check if it was the key, or just the closest match */ 
    if ((in->mode == OPEN && 
        (candidate < in->key || candidate > in->sibling)) ||
        (in->mode == CLOSE &&
        (candidate > in->key || candidate < in->sibling))) {
      pos = candidate > in->key ? 1 : 0; 
      /* If a external node exists, descend. */ 
      if (in->external_nodes[pos] == 0) { 
        ATOMIC_INC(tree->misses);
        return 0; 
      } 
      ex = btree_external_node(tree, in->external_nodes[pos]); 
      continue; 
    }
    /* Key does not exist */ 
    else if (in->mode == NONE) { 
      ATOMIC_INC(tree->misses);
      return 0;
    } 
    /* Key matched */ 
    else { 
      ATOMIC_INC(tree->hits);
      return 1;
    } 
  } 
}




/* Closes a btree */
void btree_close(
    btree_t *tree)
{
  write_btree_header(tree);
  if (tree)
    free(tree);
}



/* Delete a node from a btree */
int btree_delete(
    btree_t *tree,
    uint32_t key)
{
  assert(tree);

  btree_ex_node_t *ex;
  btree_ex_node_t *ex_orig;
  btree_in_node_t *in;
  btree_in_node_t *ne;
  enum verdict v;

  if (!find_node(tree, key, &ex, &in))
    return 0;

  ex_orig = ex;
  /* Fetch in-order successor */
  if (!get_next(tree, in, &ex, &ne)) {
    /* If no successor, we must be a leaf - so delete */
    v = btree_internal_delete(ex, in, 0);
    /* If here we must be a single root node */
    if (v == DELETE) {
      btree_external_delete(tree, ex); 
    }
    else if (v == REBALANCE) {
      btree_rebalance(tree, ex);
    }
  }
  else {
    /* Copy the in-order successors key over the top of our target */
    in->key = ne->key;
    in->sibling = ne->sibling;
    in->mode = ne->mode;
    /* Now try to delete the successor */
    v = btree_internal_delete(ex, ne, 0);
    if (v == DELETE)
      assert(1==0); /* I dont think this can ever happen */
    else if (v == REBALANCE)
      btree_rebalance(tree, ex);
  }

  return 1;
}
