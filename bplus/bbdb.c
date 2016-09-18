#include "bbdb.h"

#define LOCK(tree) pthread_rwlock_rdlock(&tree->lock)
#define UNLOCK(tree) pthread_rwlock_unlock(&tree->lock)
#define WLOCK(tree) pthread_rwlock_wrlock(&tree->lock)

static int read_bbdb_header(
     bbdb_t *bbdb)
{
  assert(bbdb);

  struct iovec vecs[BBDH_NAME_NUM+3];
  int fd = bbdb->fd;
  int i;

  /* Assign vecs */
  vecs[0].iov_base = &bbdb->version;
  vecs[0].iov_len = sizeof(bbdb->version);

  vecs[1].iov_base = &bbdb->revelation;
  vecs[1].iov_len = sizeof(bbdb->revelation);

  vecs[2].iov_base = &bbdb->num_names;
  vecs[2].iov_len = sizeof(bbdb->num_names);

  /* Reads the names used to generate the file
     this is used for mergers and collapses
   */
  for (i=0; i < BBDH_NAME_NUM; i++) {
    vecs[i+3].iov_base = &bbdb->names[i];
    vecs[i+3].iov_len = BBDH_NAME_SIZE;
  }

  if (preadv(fd, vecs, 35, BBDB_HDR_OFFSET) < 0)
    return 0;

  return 1;
}

static int write_bbdb_header(
     bbdb_t *bbdb)
{
  assert(bbdb);

  struct iovec vecs[BBDH_NAME_NUM+3];
  int fd = bbdb->fd;
  int i;

  /* Assign vecs */
  vecs[0].iov_base = &bbdb->version;
  vecs[0].iov_len = sizeof(bbdb->version);

  vecs[1].iov_base = &bbdb->revelation;
  vecs[1].iov_len = sizeof(bbdb->revelation);

  vecs[2].iov_base = &bbdb->num_names;
  vecs[2].iov_len = sizeof(bbdb->num_names);

  /* Dumps the names used to generate the file
     this is used for diffs and collapses
   */
  for (i=0; i < BBDH_NAME_NUM; i++) {
    vecs[i+3].iov_base = &bbdb->names[i];
    vecs[i+3].iov_len = BBDH_NAME_SIZE;
  }

  if (pwritev(fd, vecs, 35, BBDB_HDR_OFFSET) < 0)
    return 0;

  return 1;
}



/* Sets the enforcement mode of bbdb */
void bbdb_set_enforce(
    bbdb_t *bbdb,
    bool enforcement)
{
  WLOCK(bbdb);
  /* Only do this if the database passes verification */
  if (bbdb->crypto->pristine)
    bbdb->enforce = enforcement;
  UNLOCK(bbdb);
}



/* Get enforcement state of bbdb */
void bbdb_enforcing(
    bbdb_t *bbdb)
{
  bool enforcing;
  LOCK(bbdb);
  enforcing = bbdb->enforce;
  UNLOCK(bbdb);
  return;
}



/* Get the file path currently in use,
   This must be freed by the caller
 */
char * bbdb_path(
    bbdb_t *bbdb)
{
  char *path;
  LOCK(bbdb);
  path = strdup(bbdb->path);
  UNLOCK(bbdb);
  return path;
}



/* Get the active file descriptor used by bbdb */
int bbdb_fd(
    bbdb_t *bbdb)
{
  int fd;
  LOCK(bbdb);
  fd = bbdb->fd;
  UNLOCK(bbdb);
  return fd;
}



/* Add a name to the bbdb */
int bbdb_add_name(
    bbdb_t *bbdb,
    char *name)
{
  assert(bbdb);
  assert(name);

  char *dest;
  int sz = strlen(name);
  int rc = 0;

  WLOCK(bbdb);
  /* Pretend we did it .. */
  if (sz == 0) {
    rc = 1;
    goto fin;
  }
  if (sz > 31)
    goto fin;

  dest = bbdb->names[bbdb->num_names];
  strncpy(dest, name, sz);
  bbdb->num_names++;
  rc = 1;

fin:
  UNLOCK(bbdb);

  return rc;
}



/* Get number of names from bbdb */
int bbdb_get_num_names(
    bbdb_t *bbdb)
{
  int num;
  LOCK(bbdb);
  num = bbdb->num_names;
  UNLOCK(bbdb);
  return num;
}




/* Get name from bbdb. The caller must free the string */
char * bbdb_get_name(
    bbdb_t *bbdb,
    int num)
{
  char *nm = NULL;

  LOCK(bbdb);

  if (num < 0 || num >= bbdb->num_names)
    goto fin;
  nm = strdup(bbdb->names[num]);

fin:
  UNLOCK(bbdb);
  return nm;
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
  bbdb->detached = false;
  pthread_rwlock_init(&bbdb->lock, NULL);

  bbdb->num_names = 0;
  memset(bbdb->names, 0, sizeof(bbdb->names));

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
  bbdb->tree = btree_new(bbdb->map, bbdb->index);
  if (!bbdb->tree)
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
    if (bbdb->tree)
      btree_close(bbdb->tree);
    if (bbdb->index)
      index_close(bbdb->index);
    if (bbdb->map)
      pagemap_close(bbdb->map);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    pthread_rwlock_destroy(&bbdb->lock);
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
  bbdb->enforce = true;
  bbdb->detached = false;
  pthread_rwlock_init(&bbdb->lock, NULL);

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
  bbdb->tree = btree_open(bbdb->map, bbdb->index);
  if (!bbdb->tree)
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
    if (bbdb->tree)
      btree_close(bbdb->tree);
    if (bbdb->index)
      index_close(bbdb->index);
    if (bbdb->map)
      pagemap_close(bbdb->map);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    pthread_rwlock_destroy(&bbdb->lock);
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
enum verdict bbdb_insert(
    bbdb_t *bbdb,
    char *ip,
    enum verdict verdict)
{
  assert(bbdb);
  assert(ip);
  assert(verdict > NONE && verdict < ERROR);
  uint32_t addr;

  LOCK(bbdb);
  if (bbdb->detached) {
    UNLOCK(bbdb);
    return DETACHED;
  }
  UNLOCK(bbdb);

  if (!inet_pton(AF_INET, ip, &addr))
    return ERROR;

  WLOCK(bbdb);
  verdict = btree_insert(bbdb->tree, addr, verdict);
  UNLOCK(bbdb);

  return verdict;
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

  LOCK(bbdb);
  if (bbdb->detached) {
    verdict = DEFAULT;
    goto fin;
  }

  verdict = lru_search(bbdb->lru, addr);
  /* Found in LRU */
  if (verdict != NONE)
    goto fin;

  /* Fall back to btree */
  verdict = btree_verdict(bbdb->tree, addr);
  /* Insert record into LRU */
  if (verdict != NONE)
    lru_insert(bbdb->lru, addr, verdict);
  else
    lru_insert(bbdb->lru, addr, DEFAULT);

fin:
  UNLOCK(bbdb);
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
    if (bbdb->tree)
      btree_close(bbdb->tree);
    if (bbdb->index)
      index_close(bbdb->index);
    if (bbdb->map)
      pagemap_close(bbdb->map);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    pthread_rwlock_destroy(&bbdb->lock);
    write_bbdb_header(bbdb);
    close(bbdb->fd);
    free(bbdb);
  }
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

  WLOCK(bbdb);

  if (!crypto_certificate_set(bbdb->crypto, certificate))
    goto fin;
  if (!crypto_certificate_set_private_key(bbdb->crypto, privatekey))
    goto fin;
  if (!crypto_seal(bbdb->crypto))
    goto fin;
  if (bbdb->crypto->pristine)
    rc = 1;

fin:
  UNLOCK(bbdb);
  return rc;
}



/* Collaspes two bbdbs, making destinaton a resulting
   merger of the two bbdbs
 */
int bbdb_collaspe(
    bbdb_t *source,
    bbdb_t *destination)
{

}

#undef LOCK
#undef WLOCK
#undef UNLOCK
#undef BBDB_LOCK
