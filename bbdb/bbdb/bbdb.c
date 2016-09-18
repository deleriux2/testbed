#include "bbdb.h"

static int read_bbdb_header(bbdb_t *bbdb);
static int write_bbdb_header(bbdb_t *bbdb);

static int read_bbdb_header(
     bbdb_t *bbdb)
{
  assert(bbdb);

  struct iovec vecs[3];
  int fd = bbdb->fd;
  int i;

  /* Assign vecs */
  vecs[0].iov_base = &bbdb->version;
  vecs[0].iov_len = sizeof(bbdb->version);

  vecs[1].iov_base = &bbdb->revelation;
  vecs[1].iov_len = sizeof(bbdb->revelation);

  if (preadv(fd, vecs, 2, BBDB_HDR_OFFSET) < 0) {
    return 0;
  }

  return 1;
}


static int write_bbdb_header(
     bbdb_t *bbdb)
{
  assert(bbdb);

  struct iovec vecs[2];
  int fd = bbdb->fd;
  int i;

  if (bbdb_detached(bbdb))
    return 0;

  /* Assign vecs */
  vecs[0].iov_base = &bbdb->version;
  vecs[0].iov_len = sizeof(bbdb->version);

  vecs[1].iov_base = &bbdb->revelation;
  vecs[1].iov_len = sizeof(bbdb->revelation);

  if (pwritev(fd, vecs, 2, BBDB_HDR_OFFSET) < 0) {
    return 0;
  }

  return 1;
}





/* Sets the enforcement mode of bbdb */
void bbdb_set_enforce(
    bbdb_t *bbdb,
    bool enforcement)
{
  /* Only do this if the database passes verification */
  if (bbdb->crypto->pristine)
    bbdb->enforce = enforcement;
}



/* Get enforcement state of bbdb */
void bbdb_enforcing(
    bbdb_t *bbdb)
{
  bool enforcing;
  enforcing = bbdb->enforce;
  return;
}



/* Get the file path currently in use,
   This must be freed by the caller
 */
char * bbdb_path(
    bbdb_t *bbdb)
{
  char *path;
  path = strdup(bbdb->path);
  return path;
}



/* Get the active file descriptor used by bbdb */
int bbdb_fd(
    bbdb_t *bbdb)
{
  int fd;
  fd = bbdb->fd;
  return fd;
}



/* Creates a new BBDB file */
bbdb_t * bbdb_new(
    char *path)
{
  int fd = -1;
  bbdb_t *bbdb;
  bbdb = malloc(sizeof(bbdb_t));
  if (!bbdb)
    goto fail;

  memset(bbdb, 0, sizeof(bbdb_t));

  bbdb->path = strdup(path);
  bbdb->revelation = time(NULL);
  bbdb->enforce = false;
  bbdb->version = BBDB_VERSION;
  bbdb->detached = -1;

  /* Threading bits */
  pthread_cond_init(&bbdb->cond, NULL);
  pthread_mutex_init(&bbdb->lock, NULL);
  bbdb->workers = 1;

  /* Open the file, in NEW mode we truncate and clobber any existing
     file
   */
  fd = open(path, O_RDWR|O_TRUNC|O_CREAT, 0640);
  if (fd < 0)
    goto fail;
  bbdb->fd = fd;

/* Create the various structures */
  bbdb->map = pagemap_new(fd);
  if (!bbdb->map)
    goto fail;
  bbdb->index = index_new(bbdb->map);
  if (!bbdb->index)
    goto fail;
  bbdb->deny = btree_new(bbdb->map, bbdb->index, DENY_HDR_OFFSET);
  if (!bbdb->deny)
    goto fail;
  bbdb->allow = btree_new(bbdb->map, bbdb->index, ALLOW_HDR_OFFSET);
  if (!bbdb->allow)
    goto fail;
  bbdb->crypto = crypto_new(bbdb->map, bbdb->index);
  if (!bbdb->crypto)
    goto fail;
  bbdb->license = license_new(bbdb->map, bbdb->index);
  if (!bbdb->license)
    goto fail;
  bbdb->lru = lru_new(LRU_SIZE, LRU_SIZE+(LRU_SIZE/2));
  if (!bbdb->lru)
    goto fail;

  if (!write_bbdb_header(bbdb))
    goto fail;

  return bbdb;
fail:
  if (bbdb) {
    if (bbdb->path)
      free(bbdb->path);
    if (bbdb->license)
      license_close(bbdb->license);
    if (bbdb->crypto)
      crypto_close(bbdb->crypto);
    if (bbdb->deny)
     btree_close(bbdb->deny);
    if (bbdb->allow)
     btree_close(bbdb->allow);
    if (bbdb->index)
      index_close(bbdb->index);
    if (bbdb->map)
      pagemap_close(bbdb->map);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    close(fd);
    free(bbdb);
  }
  return NULL;
}



/* Opens an existing BBDB file */
bbdb_t * bbdb_open(
    char *path)
{
  int fd = -1;
  bbdb_t *bbdb;
  bbdb = malloc(sizeof(bbdb_t));
  if (!bbdb)
    goto fail;

  memset(bbdb, 0, sizeof(bbdb_t));

  bbdb->path = strdup(path);
  if (!bbdb->path)
    goto fail;
  bbdb->enforce = true;
  bbdb->detached = -1;

  /* Threading bits */
  pthread_cond_init(&bbdb->cond, NULL);
  pthread_mutex_init(&bbdb->lock, NULL);
  bbdb->workers = 1;

  fd = open(path, O_RDWR);
  if (fd < 0)
    goto fail;
  bbdb->fd = fd;

  /* Open the various structures */
  bbdb->map = pagemap_open(fd);
  if (!bbdb->map)
    goto fail;
  bbdb->index = index_open(bbdb->map);
  if (!bbdb->index)
    goto fail;
  bbdb->deny = btree_open(bbdb->map, bbdb->index, DENY_HDR_OFFSET);
  if (!bbdb->deny)
    goto fail;
  bbdb->allow = btree_open(bbdb->map, bbdb->index, ALLOW_HDR_OFFSET);
  if (!bbdb->allow)
    goto fail;
  bbdb->crypto = crypto_open(bbdb->map, bbdb->index);
  if (!bbdb->crypto)
    goto fail;
  bbdb->license = license_open(bbdb->map, bbdb->index);
  if (!bbdb->license)
    goto fail;
  bbdb->lru = lru_new(LRU_SIZE, LRU_SIZE+(LRU_SIZE/2));
  if (!bbdb->lru)
    goto fail;

  if (!write_bbdb_header(bbdb))
    goto fail;

  if (!bbdb->crypto->pristine)
    bbdb->enforce = 0;
  return bbdb;
fail:
  if (bbdb) {
    if (bbdb->path)
      free(bbdb->path);
    if (bbdb->license)
      license_close(bbdb->license);
    if (bbdb->crypto)
      crypto_close(bbdb->crypto);
    if (bbdb->deny)
      btree_close(bbdb->deny);
    if (bbdb->allow)
      btree_close(bbdb->allow);
    if (bbdb->index)
      index_close(bbdb->index);
    if (bbdb->map)
      pagemap_close(bbdb->map);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    close(fd);
    free(bbdb);
  }
  return NULL;
}




/* Insert an IP address into the databse. Returns:
   DUPLICATE on a matching entry which has a higher verdict
             precedence,
   NONE      when an entry with said value never previously
             existed
   verdict   Returns the OLD verdict if the key previously matched
             another entry.
   ERROR     The key given was not a valid ipv4 address.
 */
int bbdb_insert(
    bbdb_t *bbdb,
    char *ip_start,
    char *ip_end,
    enum verdict verdict)
{
  assert(bbdb);
  assert(ip_start);
  assert(ip_end);
  assert(verdict == ALLOW || verdict == DROP);

  int rc;
  uint32_t startaddr, endaddr;

  if (bbdb_detached(bbdb))
    return 0;

  if (!inet_pton(AF_INET, ip_start, &startaddr))
    return 0;
  if (!inet_pton(AF_INET, ip_end, &endaddr))
    return 0;

  startaddr = ntohl(startaddr);
  endaddr = ntohl(endaddr);

  if (verdict == DROP)
    rc = btree_insert(bbdb->deny, startaddr, endaddr+1);
  else if (verdict == ALLOW)
    rc = btree_insert(bbdb->allow, startaddr, endaddr+1);

  return rc;
}



/* Returns the verdict from the database */
enum verdict bbdb_verdict(
    bbdb_t *bbdb,
    char *ip)
{
  assert(bbdb);
  assert(ip);

  uint32_t addr;
  enum verdict verdict;
  if (!inet_pton(AF_INET, ip, &addr))
    return ERROR;

  addr = ntohl(addr);

  if (bbdb_detached(bbdb)) 
    return DEFAULT;

  verdict = lru_search(bbdb->lru, addr);
  /* Found in LRU */
  if (verdict != NOTFOUND)
    goto fin;

  /* Fall back to btree */
  if (btree_verdict(bbdb->allow, addr)) {
    verdict = ALLOW;
    lru_insert(bbdb->lru, addr, ALLOW);
  }
  else if (btree_verdict(bbdb->deny, addr)) {
    verdict = DROP;
    lru_insert(bbdb->lru, addr, DROP);
  }
  else {
    verdict = DEFAULT;
    lru_insert(bbdb->lru, addr, DEFAULT);
  }

fin:
  return verdict;   
}



/* Destroy a BBDB entry. The caller must ensure its safe to do this */
void bbdb_close(
    bbdb_t *bbdb)
{
  if (bbdb) {
    if (bbdb->path)
      free(bbdb->path);
    if (bbdb->license)
      license_close(bbdb->license);
    if (bbdb->crypto)
      crypto_close(bbdb->crypto);
    if (bbdb->deny)
      btree_close(bbdb->deny);
    if (bbdb->allow)
      btree_close(bbdb->allow);
    if (bbdb->index)
      index_close(bbdb->index);
    if (bbdb->map)
      if (!pagemap_close(bbdb->map))
        perror("pagemap close error");
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    write_bbdb_header(bbdb);
    close(bbdb->fd);
    free(bbdb);
  }
}




/* Vacuums the database, reducing its size */
void bbdb_vacuum(
    bbdb_t *bbdb)
{
  assert(bbdb);
  int newcap;
  off_t newsz;

  if (bbdb_detached(bbdb))
    return;

  bbdb_detach(bbdb);

  index_vacuum(bbdb->index);
  newcap = bbdb->map->size;
  newcap += BBDB_CHUNKSIZE - (newcap % BBDB_CHUNKSIZE);
  newsz = (newcap * PAGESIZE) + PAGESIZE; 
  ftruncate(bbdb->fd, newsz);
  bbdb->map->map = mremap(bbdb->map->map, 
             bbdb->map->filesize-PAGESIZE, newsz, MREMAP_MAYMOVE);
  if (bbdb->map->map == MAP_FAILED) {
    printf("Error remapping database\n");
    exit(1);
  }
  bbdb->map->filesize = newsz;
  bbdb->map->capacity = newcap;

  bbdb_attach(bbdb);
}



/* Seals the database, preventing further modification */
int bbdb_seal(
    bbdb_t *bbdb,
    char *privatekey,
    char *certificate)
{
  assert(bbdb);
  assert(privatekey);
  assert(certificate);

  int rc = 0;

  if (bbdb_detached(bbdb))
    return 0;

  bbdb_detach(bbdb);

  if (!crypto_certificate_set(bbdb->crypto, certificate))
    goto fin;
  if (!crypto_certificate_set_private_key(bbdb->crypto, privatekey))
    goto fin;
  if (!crypto_seal(bbdb->crypto))
    goto fin;
  if (bbdb->crypto->pristine)
    rc = 1;
  else
    bbdb->enforce = false;

fin:
  bbdb_attach(bbdb);
  return rc;
}


/* Imports src bbdb to dest bbdb, making destinaton a resulting
   merger of the two bbdbs
 */
void bbdb_import(
    bbdb_t *dst,
    bbdb_t *src)
{
  assert(dst);
  assert(src);

  btree_traverse_t trav;
  int low, high;

  if (bbdb_detached(dst))
    return;
  if (bbdb_detached(src))
    return;

  bbdb_detach(dst);

  /* Iterate over sources records */
  btree_traverse_init(src->allow, &trav);

  while (btree_traverse_next(&trav, &low, &high))
    btree_insert(dst->allow, low, high);

  btree_traverse_init(src->deny, &trav);

  while (btree_traverse_next(&trav, &low, &high))
    btree_insert(dst->deny, low, high);

  bbdb_attach(dst);
}



/* Initializes a merger summary */
int bbdb_merge_init(
    bbdb_t *bbdb,
    bbdb_merge_summary_t *merge,
    bbdb_diff_summary_t *summ)
{
  assert(bbdb);
  assert(merge);

  if (bbdb_detached(bbdb))
    return 0;

  merge->bbdb = bbdb;
  merge->their_pagecount = summ->pagecount;
  merge->pagecount = bbdb->map->pagecount;
  merge->version = bbdb->version;
  merge->revelation = bbdb->revelation;
  merge->add_pageno = merge->their_pagecount;
  merge->last_pageno = -1;
  merge->numrecs = 0;
  merge->changed = 0;
  merge->added = 0;
  merge->freed = 0;
  merge->allow_nodes = bbdb->allow->node_num;
  merge->deny_nodes = bbdb->deny->node_num;
  merge->allow_recs = bbdb->allow->record_num;
  merge->deny_recs = bbdb->deny->record_num;
  merge->allow_offset = bbdb->allow->offset;
  merge->deny_offset = bbdb->deny->offset;

  return 1;
}



/* Finds new pages for the merge */
int bbdb_merge_new(
    bbdb_merge_summary_t *summ,
    bbdb_merge_record_t *merge)
{
  assert(summ);
  assert(merge);

  bbdb_t *bbdb = summ->bbdb;
  page_t *page;
  int64_t pageno;
  uint64_t magic;

  if (bbdb_detached(bbdb))
    return -1;

  /* Here is where new pages are located */
retry:
  if (summ->add_pageno < summ->pagecount) {
    pageno = index_lookup(bbdb->index, summ->add_pageno);
    /* Whatever that was, it doesn't exist anymore */
    if (pageno < 0) {
      summ->add_pageno++;
      goto retry;
    }
    page = page_get(bbdb->map, pageno);
    magic = page_get_magic(page);

    summ->add_pageno++;

    /* Dont include indexes, freed pages or unallocated pages */
    if (magic == BBDB_MAGIC_INDEX || magic == BBDB_MAGIC_FREE
         || (magic & BBDB_MAGIC_HDR) != BBDB_MAGIC_HDR) {
      return 0;
    }
    merge->type = MERGE_TYPE_ADDED;
    merge->pageno = page_get_index(page);
    merge->magic = page_get_magic(page);
    memcpy(merge->checksum, page_get_checksum(page), SHA256_DIGEST_LENGTH);
    memcpy(merge->data, page_get_data(page), DATALEN);
    summ->added++;
    summ->numrecs++;
    return 1;
  }
  else {
    return -1;
  }
}




/* Performs a differential analysis on the 
   diff records and produces pages for non
   matching cheksums */
int bbdb_merge_next(
    bbdb_merge_summary_t *summ,
    bbdb_diff_record_t *diff,
    bbdb_merge_record_t *merge)
{

  /* Needs to find a way to end diff streams */

  assert(summ);
  assert(diff);
  assert(merge);

  page_t *page;
  int64_t pageno;
  bbdb_t *bbdb = summ->bbdb;
  char *checksum;

  if (bbdb_detached(bbdb))
    return -1;

  if (diff->pageno < 0 || diff->pageno > 4098304) {
    return -1;
  }

  pageno = index_lookup(bbdb->index, diff->pageno);
  /* This particular page no longer exists */
  if (pageno < 0) {
    merge->type = MERGE_TYPE_FREED;
    merge->pageno = diff->pageno;
    merge->magic = BBDB_MAGIC_FREE;
    memset(merge->checksum, 0, SHA256_DIGEST_LENGTH);
    memset(merge->data, 0, DATALEN);
    summ->numrecs++;
    summ->freed++;
    return 1;
  }

  page = page_get(bbdb->map, pageno);
  assert(page);

  /* Captures changed pages */
  checksum = page_get_checksum(page);
  /* Checksums match, no changes needed */
  if (memcmp(checksum, diff->checksum, SHA256_DIGEST_LENGTH) == 0) {
    return 0;
  }

  merge->pageno = diff->pageno;
  merge->new_pageno = page_get_index(page);
  merge->magic = page_get_magic(page);
  memcpy(merge->checksum, checksum, SHA256_DIGEST_LENGTH);
  memcpy(merge->data, page_get_data(page), DATALEN);
  summ->numrecs++;
  if (merge->magic == BBDB_MAGIC_FREE) {
    merge->type = MERGE_TYPE_FREED;
    summ->freed++;
  }
  else {
    merge->type = MERGE_TYPE_CHANGED;
    summ->changed++;
  }

  if (summ->last_pageno < diff->pageno)
    summ->last_pageno = diff->pageno;

  return 1;

}



/* Initializes a difference summary */
int bbdb_diff_init(
    bbdb_t *bbdb,
    bbdb_diff_summary_t *diff)
{
  assert(bbdb);
  assert(diff);

  if (bbdb_detached(bbdb))
    return 0;

  diff->current_page = -1;
  diff->bbdb = bbdb;
  diff->pagecount = bbdb->map->pagecount;
  diff->version = bbdb->version;
  diff->revelation = bbdb->revelation;

  return 1;
}



/* Retrieves the next diff */
int bbdb_diff_next(
    bbdb_diff_summary_t *summ,
    bbdb_diff_record_t *diff)
{
  assert(summ);
  assert(diff);

  bbdb_t *bbdb = summ->bbdb;
  page_t *page;
  uint8_t *chk;
  uint64_t m;
  int64_t pageno;

  if (bbdb_detached(bbdb))
    return 0;

retry:
  summ->current_page++;
  if (summ->current_page < summ->pagecount) {
    pageno = index_lookup(bbdb->index, summ->current_page);
    /* There is in such page */
    if (pageno < 0)
      goto retry;

    page = page_get(bbdb->map, summ->current_page);
    assert(page);

    m = page_get_magic(page);
   /* Dont send indexes, freed pages, or unallocated pages */
    if (m == BBDB_MAGIC_INDEX || m == BBDB_MAGIC_FREE 
           || (m & BBDB_MAGIC_HDR) != BBDB_MAGIC_HDR) 
      goto retry;

    diff->pageno = page_get_index(page);
    chk = page_get_checksum(page);
    memcpy(diff->checksum, chk, SHA256_DIGEST_LENGTH);
  }
  else {
    pagemap_quiesce_pages(bbdb->map);
    return 0;
  }

  return 1; 
}




int bbdb_apply_merge_init(
    bbdb_t *bbdb,
    bbdb_merge_summary_t *merge)
{
  assert(bbdb);
  assert(merge);

  merge->bbdb = bbdb;
  merge->last_pageno = 0;
  merge->add_pageno = 0;
  merge->their_pagecount = merge->pagecount;
  merge->pagecount = bbdb->map->pagecount;

  if (bbdb_detached(bbdb))
    return -1;

 /* Begin preparation work for the trees */
  bbdb_detach(bbdb);

  /* If their size is greater than our size, extend the mapping */
  if (merge->their_pagecount > bbdb->map->pagecount) {
    while ((merge->their_pagecount - bbdb->map->pagecount) + bbdb->map->size >
            bbdb->map->capacity) {
      if (!pagemap_extend(bbdb->map)) {
        return 0;
      }
    }
  }

  /* Set the offsets and records */
  bbdb->deny->node_num = merge->deny_nodes;
  bbdb->deny->record_num = merge->deny_recs;
  bbdb->deny->offset = merge->deny_offset;
  bbdb->allow->node_num = merge->allow_nodes;
  bbdb->allow->record_num = merge->allow_recs; 
  bbdb->allow->offset = merge->allow_offset;

  return 1;
}




int bbdb_apply_merge_next(
    bbdb_merge_summary_t *summ,
    bbdb_merge_record_t *merge)
{
  assert(summ);
  assert(merge);

  page_t *page;
  int64_t pageno;
  bbdb_t *bbdb = summ->bbdb;
  char *checksum;
  char *data;

  if (!bbdb_detached(bbdb))
    return -1;

  if (summ->last_pageno >= summ->numrecs) {
    bbdb_vacuum(bbdb);
    pagemap_quiesce_pages(bbdb->map);
    crypto_verify(bbdb->crypto);
    if (!bbdb->crypto->pristine)
      bbdb->enforce = 0;
    else
      bbdb->enforce = 1;
    lru_flush();
    bbdb_attach(bbdb);
    return 0;
  }

  if (merge->type == MERGE_TYPE_ADDED) {
    page = page_init(bbdb->map, merge->magic);
    if (!page) {
      return -1;
    }
    page_set_index(page, merge->pageno);
    index_add(bbdb->index, page);
    checksum = page_get_checksum(page);
    data = page_get_data(page); 
    memcpy(checksum, merge->checksum, SHA256_DIGEST_LENGTH);
    memcpy(data, merge->data, DATALEN);
  }
  else if (merge->type == MERGE_TYPE_CHANGED) {
    pageno = index_lookup(bbdb->index, merge->pageno);
    page = page_get(bbdb->map, pageno);
    if (!page) {
      return -1;
    }
    /* Copy over the page data with the new data */
    page_set_magic(page, merge->magic);
    checksum = page_get_checksum(page);
    memcpy(checksum, merge->checksum, SHA256_DIGEST_LENGTH);
    data = page_get_data(page);
    memcpy(data, merge->data, DATALEN);
  }
  else if (merge->type == MERGE_TYPE_FREED) {
    pageno = index_lookup(bbdb->index, merge->pageno);
    page = page_get(bbdb->map, pageno);
    if (!page) {
      return -1;
    }
    page_wipe(page);
  }

  summ->last_pageno++;
  return 1;
}


/* Adds a value to the work queue */
void bbdb_connect(
    bbdb_t *bbdb)
{
  assert(bbdb);
  ATOMIC_INC(bbdb->workers);
}

void bbdb_disconnect(
    bbdb_t *bbdb)
{
  assert(bbdb);
  ATOMIC_DEC(bbdb->workers);
}
