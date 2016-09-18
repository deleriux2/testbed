#include "blitz.h"





/* 
Range insertion algorithm:
  Make a sliding 'window' node which shifts left on all the lefts intil its too big.
  Right on the right on all the rights until its too small.
- Window left and right right are at the same median offset at the start.
  The resulting window either:
  -- Shifts to the right a certain distance.
  -- Shifts to the left a certain disatance.
  -- 'falls off' the node on the left.
  -- 'falls off' the node on the right.
  -- 'falls off' both directions.

To 'collapse' a node refers to pruning the child nodes tree in one of the directions

candidate             comparing_key

low           >=       low 
high          <=       high
- Do nothing. Matches range.

low           <        low
high          <        high
- Go left a node.

low           >        low
high          >        high
- Go right a node.


low           >=       low
high          >        high
- Move window_right by one.
- Mark right child node for collapse.


low           <        low
high          <=       high
- Move window_left by one.
- Mark left child node for collapse.


low           <        low
high          >        high
- Mark left child node for collapse.
- Mark right child node for collapse.

If window distance > 0:
- Set leftmost key_low to candidate key_low.
- Set rightmost key_high to candidate key_high.

If the left window moves entirely to the left and distance to the left window is > 0.
- Proceed down the leftmost left node. 
- Mark all nodes to the median immediate right for collapse.
- Mark intervening left nodes for collapse you travel left
  where your candidate is still lower than comparing_key.
- Continue left until you find a left node thats greater than yours.
- Copy this key, and its leftmost siblings to the leftmost node of the parent.

If the right window moves entirely to the right and distance to the left window is > 0.
- Proceed down the rightmost right node.
- Collapse all the nodes on the median left.
- Collapse intervening right nodes as you travel right
  where your candidate is higher than comparing_key.
- Continue right until you find a right node that is lower than yours.
- Copy this key, and its rightmost siblings to the rightmost node of the parent.

If at the end of the node and window distance == 0:
- Proceed down to the next node.

If at the bottom of the tree and window distance is 0. Insert node using standard insertion/splitting rules.

*/

/* 
Range deletion algorithm
  Make a sliding 'window' node which shifts left on all the lefts until its too big.
  Right on the right on all the rights until its too small.
- Window left and right right are at the same median offset at the start.
  The resulting window either:
  -- Shifts to the right a certain distance.
  -- Shifts to the left a certain disatance.
  -- 'falls off' the node on the left.
  -- 'falls off' the node on the right.
  -- 'falls off' both directions.

candidate             comparing_key

low           >=       low 
high          <=       high
- Change comparing key_high in left window to candidate key_high.
- Change comparing key_low in right window to candidate key_low.

low           <        low
high          <        high
- Go left a node.

low           >        low
high          >        high
- Go right a node.


low           >=       low
high          >        high
- Move window_right by one.
- Mark right child node for collapse.


low           <        low
high          <=       high
- Move window_left by one.
- Mark left child node for collapse.


low           <        low
high          >        high
- Mark left child node for collapse.
- Mark right child node for collapse.

If window > 0:
  - Collapse nodes between left window and right window.
*/


/*
Collapse algorithm when external node is partially collapsed.
1. Iterate over leftmost_window_node->right all intervening keys, rightmost_window_node->left.
   Pruning the entire sublitz as you go.
2. Take rightmost_window_node->right, make it leftmost_window_node->right.
3. Make leftmost_window_node->key_high rightmost_window_node->key_high.
4. Delete rightmost_window_node without running the delete algorithm.

5a. If you are left to the parent, make key_low of left sibling of parent new median key_low of this node.
5b. If you are right to the parent, make key_high of the right sibling of the parent new median key_high of this node.
5a. If the collapsing node is >= size/2, do nothing. Depth remains preserved.
5b. If the collapsing node is < size/2 and not a leaf or root. Take the parent node.
    - Place it to the right if your left of the node.
    - Place it to the left if your to the right of the node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right the new left pointer of your node.
    - If the parent is/was root and the last key. Delete that node.
      - Make your node (which has < size/2) the new root.
    - Repeat step 5b on the parent.
5c. If the collasping node is a leaf and size == 0. Take the parent node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right node the new left pointer of your node.
    - Zero the leaf pointers on the parent which now resides in your leaf.
    - If the parent is/was root and the only key left, delete that node.
      - Make your node (which has size/2) the new root.
    - Repeat step 5b on the parent.
*/

/*
Collapse algorithm when external node is entirely collapsed.
1. Prune the entire external node sublitz.
2. Run delete algorithm on parent key.
*/

/*
Delete algorithm.
1. Make left siblings right the node of your right sibling.
   Make right sibings left the node of your left sibling.
2. Delete the key from the external node.
3a. If you are left to the parent, make key_low of left side of parent parent new median key_low of this node.
3b. If you are right to the parent, make key_high of the right side of the parent new median key_high of this node.
4a. If the collapsing node is >= size/2, do nothing. Depth remains preserved.
4b. If the collapsing node is < size/2 and not a leaf or root. Take the parent node.
    - Place it to the right if your left of the node.
    - Place it to the left if your to the right of the node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right the new left pointer of your node.
    - If the parent is/was root and the last key. Delete that node.
      - Make your node (which has < size/2) the new root.
    - Repeat step 4b on the parent.
4c. If the collasping node is a leaf and size == 0. Take the parent node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right node the new left pointer of your node.
    - If the parent is/was root and the only key left, delete that node.
      - Make your node (which has size/2) the new root.
    - Repeat step 4b on the parent.
*/






static blitz_ex_node_t * blitz_external_node_init(
    blitz_t *tree, 
    int64_t upidx)
{
  assert(tree);
  assert(upidx >= 0);

  /* Initialize page */
  page_t *page;
  blitz_ex_node_t *ex;
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

static inline blitz_ex_node_t * blitz_external_node(
    blitz_t *tree,
    int64_t offset)
{
  assert(tree);
  assert(offset >= 0);
  blitz_ex_node_t *ex;

  int64_t pageno; 

  pageno = index_lookup(tree->index, offset);
  if (!index_lookup)
    return NULL;

  ex = page_get_data_of(tree->map, pageno, BBDB_MAGIC_EXNODE);

  assert(ex);
  return ex;
}

static inline blitz_in_node_t * blitz_internal(
   blitz_ex_node_t *ex,
   int offset)
{
  assert(ex);
  assert(offset >= 0 && offset < TREE_NUM_INTERNAL_NODES);
  return &ex->keys[offset];
}

static enum verdict blitz_insert_internal(
    blitz_ex_node_t *ex,
    blitz_in_node_t *in,
    uint32_t key_low,
    uint32_t key_high,
    uint64_t left,
    uint64_t right)
{
  assert(ex);
  assert(in);
  assert(key_low <= key_high);

  /* Our relative position in the index */
  int idx = in - ex->keys;

  /* Case 1: Going into an empty node */
  if (ex->size == 0) {
    in->key_low = key_low;
    in->key_high = key_high;
    in->external_nodes[0] = left;
    in->external_nodes[1] = right;
    in->used = 1;
    ex->size++;
    return NONE;
  }
  /* Case 2: Existing smaller than new key
   * Move once to the right, shift all values by right one. */
  else if (key_low > in->key_low)
    in++;
  memmove((in+1), in, (ex->size-idx) * sizeof(*in));
  ex->size++;
  ex->offset = ex->size / 2;
  in->key_low = key_low;
  in->key_high = key_high;
  in->external_nodes[0] = left;
  in->external_nodes[1] = right;
  in->used = 1;

  if (ex->size >= TREE_NUM_INTERNAL_NODES)
    return SPLIT;
  else
    return NONE;
}




/* Performs a binary search for the closest matching internal node */
static blitz_in_node_t * blitz_find_internal(
   blitz_ex_node_t *ex,
   int key)
{
  assert(ex);

  int first, middle, last;
  blitz_in_node_t *in = NULL;
  first = 0;
  last = ex->size-1;
  middle = ex->size/2;

  if (ex->size <= 0)
    return &ex->keys[0];

  while (first <= last) {
    in = &ex->keys[middle];

    if (key >= in->key_low && key <= in->key_high && in->used != 0)
      return in;

    if (key > in->key_high)
      first = middle+1;  
    else if (key < in->key_low)
      last = middle - 1;

    middle = (first + last) / 2;
  }

  if (in > &ex->keys[ex->size])
    in = &ex->keys[ex->size-1];
  else if (in < ex->keys)
    in = &ex->keys[0];

  return in;
}







static int read_blitz_header(
    blitz_t *tree)
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

  if (preadv(tree->map->fd, vecs, 3, BLITZ_HDR_OFFSET) < 0)
    return 0;

  tree->offset = pageno;
  tree->record_num = records;
  tree->node_num = nodes;
  
  return 1;
}

static int write_blitz_header(
    blitz_t *tree)
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

  if (pwritev(tree->map->fd, vecs, 3, BLITZ_HDR_OFFSET) < 0)
    return 0;

  return 1;
}



/* Create a new blitz */
blitz_t * blitz_new(
    pagemap_t *map,
    index_t *index)
{
  assert(map);
  assert(index);

  blitz_t *tree;
  tree = malloc(sizeof(blitz_t));
  if (!tree)
    goto fail;

  tree->map = map;
  tree->index = index;
  tree->node_num = 0;
  tree->record_num = 0;
  tree->offset = 0;

  if (!write_blitz_header(tree))
    goto fail;

  return tree;

fail:
  if (tree)
    free(tree);
  return NULL;
}

static int blitz_external_node_wipe(
    blitz_t *tree,
    blitz_ex_node_t *ex)
{
  int idx = page_get_index_of(ex);
  page_t *page;

  idx = index_lookup(tree->index, idx);
  if (idx < 0)
    return 0;

  page = page_get(tree->map, idx);
  if (!page)
    return 0;
  if (index_remove(tree->index, page) < 0)
    return 0;

  page_wipe(page);
  return 1;
}

static void prune_tree(
    blitz_t *tree,
    blitz_ex_node_t *ex)
{
  blitz_in_node_t *in;
  blitz_ex_node_t *visit;
  int i;
  for (i=0; i < ex->size; i++) {
    in = &ex->keys[i];
    if (in->external_nodes[0]) {
      visit = blitz_external_node(tree, in->external_nodes[0]);
      prune_tree(tree, visit);
    }
  }
  /* Prune the rightmost right node */
  in = &ex->keys[i];
  if (in->external_nodes[1]) {
    visit = blitz_external_node(tree, in->external_nodes[1]);
    prune_tree(tree, visit);
  }
  /* Perform the prune */
  blitz_external_node_wipe(tree, ex);
}

static void blitz_internal_delete(
    blitz_ex_node_t *ex,
    blitz_in_node_t *in)
{
  /* Find the offset of this internal node */
  int offset = in - ex->keys;
  int diff;
  /* Shift all the nodes right of this node one
     to the left
   */
  ex->size--;
  diff = ex->size - offset;
  if (offset < ex->size) {
    memcpy(&ex->keys[offset], &ex->keys[offset+1], 
                     diff * sizeof(blitz_in_node_t));
  }
  /* Wipe the end node */
  memset(&ex->keys[ex->size], 0, sizeof(blitz_in_node_t));
}


static blitz_in_node_t * find_parent(
    blitz_ex_node_t *ex,
    int64_t idx)
{
  int i;
  blitz_in_node_t *in;
  /* We could be the left-most node */
  if (ex->keys[0].external_nodes[0] == idx)
    return in;

  for (i=0; i < ex->size; i++) {
    in = &ex->keys[i];
    if (in->external_nodes[1] == idx)
      return in;
  }

  return NULL;
}


static void downgrade_parent(
    blitz_t *tree,
    blitz_ex_node_t *ex)
{
/*
5b. If the collapsing node is < size/2 and not a leaf or root. Take the parent node.
    - Place it to the left if your to the right of the node.
    - Place it to the right if your to the left of the node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right the new left pointer of your node.
    - If the parent is/was root and the last key. Delete that node.
      - Make your node (which has < size/2) the new root.
    - Repeat step 5b on the parent.
*/
  assert(tree);
  assert(ex);

  blitz_ex_node_t *ex2;
  blitz_in_node_t *in, tmp;
  blitz_in_node_t *uncle_left;
  blitz_in_node_t *uncle_right;
  int idx;
  int pos;
  bool isleaf = ex->keys[0].external_nodes[0] == 0 ? 1 : 0;

  idx = page_get_index_of(ex);

  /* There is no parent, cause we're the root node */
  if (ex->upidx == 0)
    return;

  /* No need to run this on small leaf nodes unless they empty */
  if (isleaf && size > 0)
    return;

  /* Only needs running on non leaf nodes less than half full */
  if (!isleaf && size >= (TREE_NUM_INTERNAL_NODES/2))
    return;

  /* Take the parent node */
  ex2 = blitz_external_node(tree, ex->upidx);
  in = find_parent(ex2, idx);
  memcpy(&tmp, in, sizeof(blitz_in_node_t));

  /* Determine what position we originate from */
  pos = in->external_nodes[0] == idx ? 0 : 1;

  /* Get the old left and right siblings of this node */
  if (in == ex2->keys)
    uncle_left = NULL;
  else
    uncle_left = in-1;
  if (in == ex2->keys[ex->offset])
    uncle_right = NULL;
  else
    uncle_right = in+1;

  /*- Make the parents old left node the new pointer of your
      positional node. */
  if (uncle_left)
    uncle_left->external_nodes[1] = in->external_nodes[pos];
  /*- Make the parents old right node the new pointer of your
      positional node. */
  if (uncle_right)
    uncle_right->external_nodes[0] = in->external_nodes[pos];
  

  /* Zero the external nodes we're a position of */
  tmp.external_nodes[po] = 0;

/*  blitz_insert_internal(ex, &ex->keys[0], in->key_low, in->key_high,
                          in->external_nodes[0], in->external_nodes[1]);
  */
}

static void collapse_range(
    blitz_t *tree,
    blitz_ex_node_t *ex,
    blitz_in_node_t *lo,
    blitz_in_node_t *hi)
{
/*
Collapse algorithm when external node is partially collapsed.
1. Iterate over leftmost_window_node->right all intervening keys, rightmost_window_node->left.
   Pruning the entire subtree as you go.
2. Take rightmost_window_node->right, make it leftmost_window_node->right.
3. Make leftmost_window_node->key_high rightmost_window_node->key_high.

5a. If you are left to the parent, make key_low of left sibling of parent new median key_low of this node.
5b. If you are right to the parent, make key_high of the right sibling of the parent new median key_high of this node.
5a. If the collapsing node is >= size/2, do nothing. Depth remains preserved.
5b. If the collapsing node is < size/2 and not a leaf or root. Take the parent node.
    - Place it to the right if your left of the node.
    - Place it to the left if your to the right of the node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right the new left pointer of your node.
    - If the parent is/was root and the last key. Delete that node.
      - Make your node (which has < size/2) the new root.
    - Repeat step 5b on the parent.
5c. If the collapsing node is a leaf and size == 0. Take the parent node.
    - Make the parents old left node the new right pointer of your node.
    - Make the parents old right node the new left pointer of your node.
    - Zero the leaf pointers on the parent which now resides in your leaf.
    - If the parent is/was root and the only key left, delete that node.
      - Make your node (which has size/2) the new root.
    - Repeat step 5b on the parent.
*/

  blitz_in_node_t *ne;
  blitz_ex_node_t *prune;
  int i;
  bool isroot = false;
  bool isleaf = false;

  /* Get status of this node */
  if (ex->upidx  == 0)
    isroot = true;
  if (ex->keys[0].external_nodes[0] == 0)
    isleaf = true;

  /* 1. Iterate over leftmost_window_node->right all intervening keys,
     rightmost_window_node->left. Pruning the entire subtree as you go.
   */
  for (ne=lo; ne < hi; ne++) {
    if (ne->external_nodes[1] == 0)
      break;
    prune = blitz_external_node(tree, ne->external_nodes[1]);
    if (prune)
      prune_tree(tree, prune);
  }
  ne = lo+1;

  /* 2. Take rightmost_window_node->right, make it leftmost_window_node->right. */
  lo->external_nodes[1] = hi->external_nodes[1];
  /* 3. Make leftmost_window_node->key_high rightmost_window_node->key_high. */
  lo->key_high = hi->key_high;

  /* Given everything shifts left each time we delete, we have no need to
   * alter the next pointer */
  /* 4. Delete rightmost_window_node without running the delete algorithm. */
  for (i=0; i < (hi-lo); i++)
    blitz_internal_delete(ex, ne);
  hi = ne;

  /* 5b. If the collapsing node is < size/2 and not a leaf or root. 
         Take the parent node. 
   */
  if (ex->size < (TREE_NUM_INTERNAL_NODES/2) && !isroot && !isleaf) {
    printf("Dont know yet what to do here.\n");
  }
  else if (isroot && ex->size == 0) {
    printf("Root has become empty!\n");
    assert(1==0);
  }
  else if (isleaf && ex->size == 0) {

  }

}



/* Insert into blitz */
enum verdict blitz_insert(
    blitz_t *tree,
    uint32_t key_low,
    uint32_t key_high)
{
  assert(tree);
  assert(key_low <= key_high);

  int pos;
  enum verdict oldv;
  blitz_ex_node_t *ex;
  blitz_in_node_t *lo, *hi;

  if (tree->offset == 0) {
    ex = blitz_external_node_init(tree, 0);
    tree->offset = page_get_index_of(ex);
  }
  else {
    ex = blitz_external_node(tree, tree->offset);
  }
  assert(ex);

  lo = blitz_internal(ex, ex->offset);
  hi = lo;
  assert(lo);

  while (1) {
    lo = blitz_find_internal(ex, key_low);
    hi = blitz_find_internal(ex, key_high);
    assert(lo);
    assert(hi);

    /* Case 1. Its the only key in the node */
    if (ex->size == 0) {
      blitz_insert_internal(ex, lo, key_low, key_high, 0, 0);
      return DEFAULT;
    }
    else if (hi-lo == 0) {
      /* Case 2: The key already exists between a node */
      if (key_low >= lo->key_low && key_high <= hi->key_high)
        return DUPLICATE;
      /* Case 3: The key reached the left of this node
                 but we're a leaf */
      if (key_low < lo->key_low && lo->external_nodes[0] == 0) {
        blitz_insert_internal(ex, lo, key_low, key_high, 0, 0);
        return DEFAULT;
      }
      /* Case 4: The key reached the right of this node
                 but we're a leaf */
      else if (key_low > hi->key_low && hi->external_nodes[1] == 0) {
        blitz_insert_internal(ex, lo, key_low, key_high, 0, 0);
        return DEFAULT;
      }
      /* Case 5: The key reached the left of this node
                 but we are not a leaf */
      else if (key_low < lo->key_low && key_high < lo->key_high) {
        pos = key_low > lo->key_low ? 1 : 0;
        ex = blitz_external_node(tree, lo->external_nodes[pos]);
      }
      /* Case 6: The key reached the right of this node
                 but we are not a leaf */
      else if (key_low > hi->key_low && key_high > hi->key_high) {
        pos = key_low > lo->key_low ? 1 : 0;
        ex = blitz_external_node(tree, lo->external_nodes[pos]);
      }
    }
    else {
      /* Case 7: Intervening nodes between these are within our range.
                 Collapse intervening nodes.
       */
      if (key_low >= lo->key_low && key_high <= hi->key_high)
        collapse_range(tree, ex, lo, hi);
    }
    exit(1);
    /* We dont need to loop yet.. */
  }
}



int main()
{
  int fd = open("test.bbd", O_RDWR|O_TRUNC|O_CREAT, 0640);
  pagemap_t *map = pagemap_new(fd);
  index_t *index = index_new(map);
  blitz_t *tree = blitz_new(map, index);
  blitz_insert(tree, 3000, 4000);
  blitz_insert(tree, 2000, 2500);
  blitz_insert(tree, 4200, 5000);
  blitz_insert(tree, 3000, 4999);
}
