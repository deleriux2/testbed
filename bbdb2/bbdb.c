#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <assert.h>

#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509_vfy.h>

#include "bbdb.h"

/* To add a new certificate do this:
 * 1. Create a new SSL certificate fully signed in DER format
 * 2. Run ld -r -b binary -o root.der.o [inputcrt_goes_here.der]
 * 3. Link the resulting root.der.o to the binary
 */

extern unsigned char _binary_root_der_start[];
extern unsigned int _binary_root_der_size;

static bbdb_ex_node_t * bbdb_external_node_init(bbdb_t *bbdb, int32_t upidx);
static inline bbdb_ex_node_t * bbdb_external(bbdb_t *bbdb, int pos);
static inline bbdb_in_node_t * bbdb_internal(bbdb_ex_node_t *ex, int pos);
static enum verdict bbdb_insert_internal(bbdb_ex_node_t *ex, bbdb_in_node_t *in, uint32_t key, enum verdict verdict, uint64_t left, uint64_t right);
static bbdb_in_node_t * bbdb_find_internal(bbdb_ex_node_t *ex, int key);
static bbdb_ex_node_t * bbdb_split(bbdb_t *bbdb, bbdb_ex_node_t *ex, uint32_t key);
static void bbdb_sparse_index(bbdb_t *bbdb, bbdb_ex_node_t *ex);
static void * bbdb_pgindx_get_page(bbdb_t *bbdb, uint64_t pos);
static void bbdb_certificate_add(bbdb_t *bbdb, X509 *cert, X509_STORE *trustdb);
//static void bbdb_certificate_verify(bbdb_t *bbdb, X509 *root);


static inline bbdb_ex_node_t * bbdb_external(
    bbdb_t *bbdb,
    int pos)
{
  assert(bbdb);
  assert(pos >= 0);
  bbdb_ex_node_t *ex;
  ex = (void *)bbdb_pgindx_get_page(bbdb, pos);
  if (!ex || ex->magic != BBDB_MAGIC_NODE) {
    return NULL;
  }
  return ex;
}

static inline bbdb_in_node_t *bbdb_internal(
   bbdb_ex_node_t *ex,
   int pos)
{
  assert(ex);
  assert(pos >= 0 && pos < NUMKEYS);
  return &ex->keys[pos];
}

static inline bbdb_sparse_entry_t * bbdb_get_sparse_table(
    bbdb_t *bbdb)
{
  if (bbdb->sparse)
    return (void *)bbdb->sparse + sizeof(bbdb_sparse_table_t);
  return NULL;
}

static inline bbdb_ipnet_t * bbdb_get_license_ipnet(
    bbdb_t *bbdb)
{
  if (bbdb->sparse)
    return (void *)bbdb->license + sizeof(bbdb_license_t);
  return NULL;
}

static inline unsigned char * bbdb_get_crypto_certificate(
    bbdb_t *bbdb)
{
  if (bbdb->crypto)
    return (void *)bbdb->crypto + sizeof(bbdb_crypto_table_t);
  return NULL;
}

static inline bbdb_crypto_entry_t * bbdb_get_crypto_table(
    bbdb_t *bbdb)
{
  if (bbdb->crypto)
    return (void *)bbdb->crypto + sizeof(bbdb_crypto_table_t) + bbdb->crypto->certsize;
  return NULL;
}

static inline bbdb_pgindx_entry_t * bbdb_get_pgindx_table(
    bbdb_t *bbdb)
{
  if (bbdb->pgindx)
    return (void *)bbdb->pgindx + sizeof(bbdb_pgindx_table_t);
  return NULL;
}


/* Creates a new external node */
#ifdef BBDB_WRITE
static bbdb_ex_node_t * bbdb_external_node_init(
    bbdb_t *bbdb,
    int32_t upidx)
{
  assert(bbdb);
  /* Get the next free page */
  bbdb_ex_node_t *ex = (void *)bbdb->map + (BBDB_PAGESIZE * (bbdb->size+1));

  /* Initialize the node */
  ex->magic = BBDB_MAGIC_NODE;
  ex->index = ++bbdb->size;
  (*bbdb->treesize)++;
  ex->offset = 0;
  ex->size = 0;
  ex->upidx = upidx;
  memset(ex->keys, 0, sizeof(ex->keys));

  return ex;
}
#endif

#ifdef BBDB_WRITE
void bbdb_build_pgindx_table(
    bbdb_t *bbdb)
{
  int64_t i;
  int sz;
  int num=0;
  bbdb_pgindx_entry_t *entries = NULL;
  bbdb_pgindx_entry_t *en = NULL;

  /* Determine the size of the index */
  sz = *bbdb->treesize;
  entries = calloc(sz, sizeof(bbdb_pgindx_entry_t));
  if (!entries)
    bbdb_err(EXIT_FAILURE, "Cannot create pageindex table");
  bbdb_ex_node_t *ex;
  for (i = 1; i <= (*bbdb->treesize); i++) {
    ex = bbdb_external(bbdb, i);
    if (!ex)
      continue;
    entries[ex->index].page = i;
    entries[ex->index].index = ex->index;
  }

  /* Assign the pgindx table */
  *bbdb->pgindxindex = bbdb->size+1;
  bbdb->pgindx = (void *)(bbdb->map + (*bbdb->pgindxindex));
  bbdb->size += (((sizeof(bbdb_pgindx_entry_t) * (*bbdb->treesize)) + sizeof(bbdb_pgindx_table_t)) / BBDB_PAGESIZE) + 1;
  bbdb->pgindx = (void *)(bbdb->map + (BBDB_PAGESIZE * (*bbdb->pgindxindex)));
  bbdb->pgindx->magic = BBDB_MAGIC_SPARSE;
  bbdb->pgindx->size = bbdb->size - (*bbdb->pgindxindex);
  en = bbdb_get_pgindx_table(bbdb);
  memcpy(en, entries, ((*bbdb->treesize)+1) * sizeof(bbdb_pgindx_entry_t));
  free(entries);
}

#endif

#ifdef BBDB_WRITE
void bbdb_build_license_table(
    bbdb_t *bbdb,
    bbdb_license_t *li)
{
  int sz;
  bbdb_ipnet_t *en = NULL;
  /* Assign the sparse table */
  *bbdb->licenseindex = bbdb->size+1;
  sz = ((sizeof(bbdb_license_t) + (sizeof(bbdb_ipnet_t) * li->ipsize)) / BBDB_PAGESIZE) + 1;
  bbdb->license = (void *)(bbdb->map + (BBDB_PAGESIZE * (*bbdb->licenseindex)));
  bbdb->license->magic = BBDB_MAGIC_LICENSE;
  bbdb->license->size = sz;
  bbdb->license->capacity = sz;
  bbdb->license->ipsize = li->ipsize;
  bbdb->license->mode = li->mode;
  bbdb->license->expiry = li->expiry;
  bbdb->license->ipsize = li->ipsize;
  bbdb->size += bbdb->sparse->capacity;
  memcpy(bbdb->license->ips, li->ips, li->ipsize * sizeof(bbdb_ipnet_t));
}
#endif

#ifdef BBDB_WRITE
int compare_sparse(
    const void *a,
    const void *b)
{
  const bbdb_sparse_entry_t *ka = a;
  const bbdb_sparse_entry_t *kb = b;
  if (ka->key > kb->key)
    return 1;
  else if (ka->key == kb->key)
    return 0;
  else
    return -1;
}

void bbdb_build_sparse_table(
    bbdb_t *bbdb)
{
  int64_t i;
  int sz;
  bbdb_sparse_entry_t *entries = NULL;
  bbdb_sparse_entry_t *en = NULL;

  /* Determine the size of the index */
  sz = *bbdb->treesize;
  entries = calloc((*bbdb->treesize), sizeof(bbdb_sparse_entry_t));
  if (!entries)
    bbdb_err(EXIT_FAILURE, "Cannot create entry table");
  bbdb_ex_node_t *ex;
  for (i = 1; i < (*bbdb->treesize); i++) {
    ex = bbdb_external(bbdb, i);
    entries[i-1].key = ex->keys[0].key;
    entries[i-1].index = ex->index;
  }
  qsort(entries, (*bbdb->treesize), sizeof(bbdb_sparse_entry_t), compare_sparse);

  /* Assign the sparse table */
  *bbdb->sparseindex = bbdb->size+1;
  sz = (((sizeof(bbdb_sparse_entry_t) * (*bbdb->treesize)) + sizeof(bbdb_sparse_table_t)) / BBDB_PAGESIZE) + 1;
  bbdb->sparse = (void *)(bbdb->map + (BBDB_PAGESIZE * (*bbdb->sparseindex)));
  bbdb->sparse->magic = BBDB_MAGIC_SPARSE;
  bbdb->sparse->size = sz;
  bbdb->sparse->capacity = sz + (sz/BBDB_RESERVE);
  bbdb->size += bbdb->sparse->capacity;
  en = bbdb_get_sparse_table(bbdb);
  memcpy(en, entries, (*bbdb->treesize) * sizeof(bbdb_sparse_entry_t));
  free(entries);
}
#endif

static int bbdb_certificate_validate(
    bbdb_t *bbdb,
    X509 *cert,
    X509_STORE *trustdb)
{
  assert(bbdb);
  assert(cert);

  /* Create a trust chain */
  X509_STORE_CTX *ctx = NULL;
  int rc = 0;

  if ((ctx = X509_STORE_CTX_new()) == NULL)
    goto fail;

  /* Init contenxt and validate */
  if (!X509_STORE_CTX_init(ctx, trustdb, cert, NULL))
    goto fail;

  if (X509_verify_cert(ctx) != 1)
    goto fail;
  rc = 1;

fail:
  X509_STORE_CTX_cleanup(ctx);
  X509_STORE_CTX_free(ctx);

  return rc;
}

#ifdef BBDB_WRITE
static void bbdb_certificate_add(
    bbdb_t *bbdb,
    X509 *cert,
    X509_STORE *trustdb)
{
  assert(bbdb);
  assert(cert);
  assert(trustdb);
  assert(bbdb->crypto);

  int rc;
  unsigned char *buf = NULL;

  if (!bbdb_certificate_validate(bbdb, cert, trustdb))
    bbdb_err(EXIT_FAILURE, "Cannot validate certificate");
  buf = bbdb_get_crypto_certificate(bbdb);
  if (!buf)
    return;

  /* Convert the certificate into DER format then write into our page */
  rc = i2d_X509(cert, &buf);
  if (rc <= 0)
    bbdb_err(EXIT_FAILURE, "Could not convert certificate into DER encoded format");

  bbdb->crypto->certsize = rc;
}
#endif

#ifdef BBDB_WRITE
static void bbdb_signiture_add(
    bbdb_t *bbdb,
    EVP_PKEY *key)
{
  int sz = 0;
  int i;
  bbdb_crypto_entry_t *en = NULL;
  const EVP_MD *dgst = EVP_sha256();
  EVP_MD_CTX *evp = EVP_MD_CTX_create();
  char buf[264];
  void *page = NULL;

  memset(buf, 0, 264);

  /* Begin signing routine */
  EVP_SignInit_ex(evp, dgst, NULL);
  en = bbdb_get_crypto_table(bbdb);
  if (!en)
    bbdb_err(EXIT_FAILURE, "cannot fetch crypto table");

  for (i=0; i < (*bbdb->treesize); i++)
    EVP_SignUpdate(evp, en[0].hash, 32);

  /* Include the license table */
  if (!bbdb->license)
    bbdb_err(EXIT_FAILURE, "License table does not exist");
  EVP_SignUpdate(evp, bbdb->license, (BBDB_PAGESIZE * bbdb->license->size));

  EVP_SignFinal(evp, buf, &sz, key);

  if (sz > 263)
    bbdb_err(EXIT_FAILURE, "Signiture wont fit into table");

  memcpy(bbdb->crypto->signiture, buf, sz);

  EVP_MD_CTX_destroy(evp);
  return;
}
#endif

#ifdef BBDB_WRITE
void bbdb_build_crypto_table(
    bbdb_t *bbdb,
    EVP_PKEY *key,
    X509 *cert,
    X509_STORE *trustdb)
{
  assert(bbdb);
  assert(key);
  assert(cert);
  assert(trustdb);

  int64_t i;
  int sz;
  int certsz = 0;
  bbdb_crypto_entry_t *entries = NULL;
  bbdb_crypto_entry_t *en = NULL;
  bbdb_ex_node_t *ex = NULL;
  void *page;
  char hash[32];
  EVP_MD_CTX *evp;
  const EVP_MD *dgst = EVP_sha256();
  evp = EVP_MD_CTX_create();
  if (!EVP_DigestInit_ex(evp, dgst, NULL))
    bbdb_err(EXIT_FAILURE, "cannot create digest instance");

  /* Determine the size of the index */
  sz = bbdb->size;
  entries = calloc((*bbdb->treesize), sizeof(bbdb_crypto_entry_t));
  if (!entries)
    bbdb_err(EXIT_FAILURE, "Cannot create entry table");

  /* Sum the btree */
  int num=0;
  for (i = 0; i < sz; i++) {
    ex = bbdb_external(bbdb, i);
    /* Must actually be an external node */
    if (!ex)
      continue;
    /* Shasum */ 
    EVP_DigestUpdate(evp, (void *)ex, BBDB_PAGESIZE);
    EVP_DigestFinal_ex(evp, hash, NULL);
    entries[num].index = ex->index;
    memcpy(entries[num].hash, hash, 32);
    EVP_DigestInit_ex(evp, dgst, NULL);
    num++;
  }

  /* Assign the crypto table */
  *bbdb->cryptindex = bbdb->size+1;
  bbdb->crypto = (void *)(bbdb->map + (BBDB_PAGESIZE * (*bbdb->cryptindex)));
  bbdb->crypto->magic = BBDB_MAGIC_VERIFY;
  /* Add the certificate */
  bbdb_certificate_add(bbdb, cert, trustdb);
  sz = ((((sizeof(bbdb_crypto_entry_t) * bbdb->size) + sizeof(bbdb_crypto_table_t)) + bbdb->crypto->certsize) / BBDB_PAGESIZE) + 1;
  bbdb->crypto->size = sz;
  bbdb->crypto->capacity = sz + (sz/BBDB_RESERVE);
  bbdb->size += bbdb->crypto->capacity;
  bbdb->crypto->numrecs = num;
  en = bbdb_get_crypto_table(bbdb);
  memcpy(en, entries, bbdb->size * sizeof(bbdb_crypto_entry_t));

  /* Add the cryptographic HMAC */
  bbdb_signiture_add(bbdb, key);
  free(entries);
  EVP_MD_CTX_destroy(evp);
}
#endif

static int bbdb_signiture_verify(
    bbdb_t *bbdb,
    X509 *cert)
{
  int i;
  bbdb_crypto_entry_t *en = NULL;
  const EVP_MD *dgst = EVP_sha256();
  EVP_PKEY *pubkey = X509_get_pubkey(cert);
  EVP_MD_CTX *evp = EVP_MD_CTX_create();
  char buf[264];
  int rc = 0;

  memset(buf, 0, 264);
  /* Extract public key from x509 certificate */

  /* Begin signing routine */
  EVP_VerifyInit_ex(evp, dgst, NULL);
  en = bbdb_get_crypto_table(bbdb);
  if (!en) {
    bbdb_warn("cannot fetch crypto table");
    goto out;
  }

  for (i=0; i < (*bbdb->treesize); i++)
    EVP_VerifyUpdate(evp, en[0].hash, 32);

  if (!bbdb->license)
    bbdb_err(EXIT_FAILURE, "License table does not exist");
  EVP_SignUpdate(evp, bbdb->license, (BBDB_PAGESIZE * bbdb->license->size));

  if (EVP_VerifyFinal(evp, bbdb->crypto->signiture, 257, pubkey) != 1) {
    warn("Pubkey verification failed");
    goto out;
  }

  rc = 1;

out:
  EVP_MD_CTX_destroy(evp);
  EVP_PKEY_free(pubkey);
  return rc;

}

int bbdb_verify_crypto_table(
    bbdb_t *bbdb,
    X509_STORE *trustdb)
{
  uint64_t i, j;
  bbdb_crypto_table_t *cr = bbdb->crypto;
  bbdb_crypto_entry_t *en = bbdb_get_crypto_table(bbdb);
  X509 *cert = NULL;
  EVP_MD_CTX *evp;
  void *page;
  const EVP_MD *dgst = EVP_sha256();
  evp = EVP_MD_CTX_create();
  char hash[32];
  int size;
  int verify_mode = BBDB_VERIFY_ALL;
  int p_no;
  const unsigned char *certbuf = NULL;
  int rc = 0;

  if (!EVP_DigestInit_ex(evp, dgst, NULL)) {
    bbdb_warn("internal error validating crypto table");
    goto end;
  }

  if (!cr) {
    bbdb_warn("Unable to find crypto table");
    goto end;
  }

  /* Validate a sample of pages at random if the number of pages exceeds a threshold */
  if (((*bbdb->treesize) * BBDB_PAGESIZE) > BBDB_VERIFY_THRESHOLD) {
    srand(time(NULL));
    size = ((*bbdb->treesize) / 100) * BBDB_VERIFY_SAMPLE_PC;
    verify_mode = BBDB_VERIFY_SAMPLE;
  }
  else
    size = (*bbdb->treesize);

  for (i=0; i < bbdb->crypto->numrecs; i++) {
    if (verify_mode == BBDB_VERIFY_ALL)
      p_no = i;
    else
      p_no = rand() % (*bbdb->treesize);
    page = bbdb_pgindx_get_page(bbdb, en[p_no].index);
    if (!page)
      goto end;
    /* Shasum */
    EVP_DigestUpdate(evp, page, BBDB_PAGESIZE);
    EVP_DigestFinal_ex(evp, hash, NULL);

    if (memcmp(en[p_no].hash, hash, 32) != 0)
      goto end;
    EVP_DigestInit_ex(evp, dgst, NULL);
  }

  certbuf = bbdb_get_crypto_certificate(bbdb);
  if ((cert = d2i_X509(NULL, &certbuf, bbdb->crypto->certsize)) == NULL)
    goto end;

  if (!bbdb_certificate_validate(bbdb, cert, trustdb)) 
    goto end;
  if (!bbdb_signiture_verify(bbdb, cert))
    goto end;
  rc = 1;

end:
  EVP_MD_CTX_destroy(evp);
  X509_free(cert);
  return rc;
  
}

static inline void * bbdb_pgindx_get_page(
    bbdb_t *bbdb,
    uint64_t pos)
{
  bbdb_pgindx_entry_t *en = bbdb_get_pgindx_table(bbdb);
  if (en)
    return (void *)bbdb->map + (en[pos].page * BBDB_PAGESIZE);
  else
    return (void *)bbdb->map + (pos * BBDB_PAGESIZE);
}


#ifdef BBDB_WRITE
/* When a external node is full this splits the node use btree semantics. */
static bbdb_ex_node_t * bbdb_split(
    bbdb_t *bbdb,
    bbdb_ex_node_t *ex,
    uint32_t key)
{
  /* 1. Take the median internal node.
   * 2. Create a new external node.
   * 3. Copy all the internal nodes to the left of this node into the new external node. Keeping in median placement.
   * 4. Clear the left nodes from the given external node. Shift the whole list of nodes appropriately to the left.
   * 5. Insert the median internal node into the parent external node of the provided external node.
   * 5. The median internal nodes left should be the new node. The right should be the given node.
  */
   assert(bbdb);
   assert(ex);
   int i;
   int oldsize = ex->size;
   bbdb_in_node_t *in = NULL;
   bbdb_in_node_t tmp, tmp2;
   bbdb_ex_node_t *newex = NULL;
   bbdb_ex_node_t *ex2 = NULL;
   bbdb_ex_node_t *up = NULL;
   bbdb_ex_node_t *upup = NULL;
   bbdb_in_node_t keys[NUMKEYS/2];

   memset(keys, 0, (NUMKEYS/2) * sizeof(bbdb_in_node_t));
  /* 1. Take the median internal node. */
   in = bbdb_internal(ex, ex->offset);
   memcpy(&tmp, in, sizeof(tmp));

   /* 2. Create a new external node */
   newex = bbdb_external_node_init(bbdb, 0);

   /* 3. Copy all the internal nodes to the left of this node into the new external node. Keeping in median placement. */
   memcpy(newex->keys, ex->keys, (ex->offset) * sizeof(bbdb_in_node_t));
   newex->size = ex->offset;
   newex->offset = ex->offset/2;

   /* 4. Clear the left nodes from the given external node. Shift the whole list of nodes appropriately to the left, remove the first node */
   memcpy(keys, &ex->keys[ex->offset+1], (ex->offset-1) * sizeof(bbdb_in_node_t));
   memset(ex->keys, 0, NUMKEYS * sizeof(bbdb_in_node_t));
   memcpy(ex->keys, keys, (ex->offset-1) * sizeof(bbdb_in_node_t));
   ex->size = ex->offset-1;
   ex->offset = ex->size/2;

   /* 5. Insert the median internal node into the parent external node of the provided external node. */
   if (ex->upidx == 0) {
      /* Special case: Make a new node, insert median into it, remark this as parent to the new root. */
      up = bbdb_external_node_init(bbdb, 0);
      in = bbdb_internal(up, up->offset);
      ex->upidx = up->index;
      newex->upidx = up->index;
      /* Given this should never fail, bail if we dont get this to work */
      if (bbdb_insert_internal(up, in, tmp.key, tmp.verdict, newex->index, ex->index) != NONE)
        bbdb_err(EXIT_FAILURE, "Something horrific happened");
      bbdb->root = up;
      *bbdb->rootindex = up->index;

     /* The internal node to the left of the new median should point to the new node on the right. */
     in = bbdb_find_internal(up, tmp.key);
     if (in != up->keys) {
       in--;
       in->external_nodes[1] = newex->index;
     }

   }
   else {
     up = bbdb_external(bbdb, ex->upidx);
     in = bbdb_find_internal(up, tmp.key);
     ex->upidx = up->index;
     newex->upidx = up->index;

     /* If the parent is full, recurse up a branch. */
     if (bbdb_insert_internal(up, in, tmp.key, tmp.verdict, newex->index, ex->index) == SPLIT) {

       /* The internal node to the left of the new median should point to the new node on the right. */
       in = bbdb_find_internal(up, tmp.key);
       if (in != up->keys) {
         in--;
         in->external_nodes[1] = newex->index;
       }
       up = bbdb_split(bbdb, up, tmp.key);
     }
     else {

       in = bbdb_find_internal(up, tmp.key);
       if (in != up->keys) {
         in--;
         in->external_nodes[1] = newex->index;
       }
     }
   }

   /* Iterate over the new external nodes child nodes, setting the correct upidx for each child */
   for (i = 0; i < newex->size; i++) {
     in = bbdb_internal(newex, i);
     if (in->external_nodes[0] == 0)
       /* All internals must be empty too in this situation */
       break;
     
     ex2 = bbdb_external(bbdb, in->external_nodes[0]);
     ex2->upidx = newex->index;
     ex2 = bbdb_external(bbdb, in->external_nodes[1]);
     ex2->upidx = newex->index;
   }

   /* Using the key provided by the input, now rescan the parent and find the closest matching node
    * this is used for recursion */
   in = bbdb_find_internal(up, key);
   return bbdb_external(bbdb, in->external_nodes[key > in->key]);
}
#endif



#ifdef BBDB_WRITE
/* Inserts a new key into the bbdb. */
static enum verdict bbdb_insert_internal(
    bbdb_ex_node_t *ex,
    bbdb_in_node_t *in,
    uint32_t key,
    enum verdict verdict,
    uint64_t left,
    uint64_t right)
{
  assert(ex);
  assert(in);

  /* Our relative position in the index */
  int idx = in - ex->keys;

  /* Case 1: Going into an empty node */
  if (ex->size == 0) {
    in->verdict = verdict;
    in->key = key;
    in->external_nodes[0] = left;
    in->external_nodes[1] = right;
    ex->size++;
    return NONE;
  }
  /* Case 2: Existing smaller than new key
   * Move once to the right, shift all values by right one. */
  else if (key > in->key)
    in++;
  memmove((in+1), in, (ex->size-idx) * sizeof(*in));
  ex->size++;
  ex->offset = ex->size / 2;
  in->verdict = verdict;
  in->key = key;
  in->external_nodes[0] = left;
  in->external_nodes[1] = right;

  if (ex->size >= NUMKEYS)
    return SPLIT;
  else
    return NONE;
}
#endif


/* Opens an existing bbdb file */
bbdb_t * bbdb_load(
    char *path,
    int cachesize,
    X509_STORE *trustdb)
{
  assert(path);
  int rc;
  struct bbdb_t *bbdb = NULL;

  /* Allocate the main structure and initialize */
  bbdb = malloc(sizeof(bbdb_t));
  if (!bbdb) {
    bbdb_warn("Cannot allocate memory");
    goto err;
  }
  /* Initialize */
  memset(bbdb->path, 0, sizeof(bbdb->path));
  bbdb->fd = -1;
  bbdb->size = 0;
  bbdb->magic = 0;
  bbdb->revelation = -1;
  bbdb->map = NULL;
  bbdb->root = NULL;
  bbdb->rootindex = NULL;
  bbdb->sparse = NULL;
  bbdb->sparseindex = NULL;
  bbdb->crypto = NULL;
  bbdb->cryptindex = NULL;
  bbdb->treesize = NULL;
  bbdb->pgindx = NULL;
  bbdb->pgindxindex = NULL;
  bbdb->license = NULL;
  bbdb->licenseindex = NULL;
  bbdb->lru = NULL;

  strncpy(bbdb->path, path, sizeof(bbdb->path)-1);

  /* Open the file */
  bbdb->fd  = open(bbdb->path, O_RDONLY);
  if (bbdb->fd < 0) {
    bbdb_warn("Cannot create new file %s", path);
    goto err;
  }

  /* Read the magic from the file */
  if (read(bbdb->fd, &bbdb->magic, sizeof(BBDB_MAGIC)) < sizeof(BBDB_MAGIC)) {
    bbdb_warn("Could not read file magic to file %s", bbdb->path);
    goto err;
  }

  if (bbdb->magic != BBDB_MAGIC) {
    bbdb_warn("Magic failed on header");
    goto err;
  }

  /* Revelation is just the unix epoch for now */
  bbdb->revelation = time(NULL);
  if (read(bbdb->fd, &bbdb->revelation, sizeof(bbdb->revelation)) < sizeof(bbdb->revelation)) {
    bbdb_warn("Could not read revelation from file %s", bbdb->path);
    goto err;
  }

  /* Map the remainder of the file into memory */
  bbdb->map = mmap(NULL, BBDB_CHUNKSIZE, PROT_READ, MAP_SHARED, bbdb->fd, 0);
  if (bbdb->map == MAP_FAILED) {
    bbdb_warn("Could not map file %s", bbdb->path);
    goto err;
  }
  bbdb->rootindex = (uint64_t *)(bbdb->map+12); 
  bbdb->sparseindex = (uint64_t *)(bbdb->map+20); 
  bbdb->cryptindex = (uint64_t *)(bbdb->map+28); 
  bbdb->treesize = (uint64_t *)(bbdb->map+36); 
  bbdb->pgindxindex = (uint64_t *)(bbdb->map+44); 
  bbdb->licenseindex = (uint64_t *)(bbdb->map+56); 
  bbdb->numrecs = (uint64_t *)(bbdb->map+64); 
  
  /* Initialize the main page tables */
  bbdb->root = (void *)bbdb->map + ((*bbdb->rootindex) * BBDB_PAGESIZE);
  bbdb->sparse = (void *)bbdb->map + ((*bbdb->sparseindex) * BBDB_PAGESIZE);
  bbdb->crypto = (void *)bbdb->map + ((*bbdb->cryptindex) * BBDB_PAGESIZE);
  bbdb->license = (void *)bbdb->map + ((*bbdb->licenseindex) * BBDB_PAGESIZE);
  bbdb->pgindx = (void *)bbdb->map + ((*bbdb->pgindxindex) * BBDB_PAGESIZE);

  /* Magic page check */
  if (bbdb->root->magic != BBDB_MAGIC_NODE) {
    bbdb_warn("Magic failed on btree root"); 
    goto err;
  }
  if (bbdb->sparse->magic != BBDB_MAGIC_SPARSE) {
    bbdb_warn("Magic failed on sparse index");
    goto err;
  }
  if (bbdb->crypto->magic != BBDB_MAGIC_VERIFY) {
    bbdb_warn("Magic failed on crypto table");
    goto err;
  }
  if (bbdb->license->magic != BBDB_MAGIC_LICENSE) {
    bbdb_warn("Magic failed on license table");
    goto err;
  }

  /* Validate database */
  if (!bbdb_verify_crypto_table(bbdb, trustdb)) {
    bbdb_warn("Database is corrupted");
    goto err;
  }

  /* Initialize the LRU */
  bbdb->lru = lru_new(cachesize, (cachesize + cachesize/2));
  bbdb->lru_hits = 0;
  bbdb->lru_misses = 0; 

  /* Inform kernel sparse index is needed */
  if (madvise(bbdb->map + (*bbdb->sparseindex * BBDB_PAGESIZE), (bbdb->sparse->size * BBDB_PAGESIZE), MADV_WILLNEED) < 0)
    bbdb_warn("Cannot set memory advise"); 
  return bbdb;

err:
  if (bbdb) {
    if (bbdb->map)
      munmap(bbdb->map, BBDB_CHUNKSIZE);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    close(bbdb->fd);
    free(bbdb);
  }
  return NULL;
}

void bbdb_close( 
    bbdb_t *bbdb)
{
  if (bbdb) {
    if (bbdb->map)
      munmap(bbdb->map, BBDB_PAGESIZE * bbdb->size);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    close(bbdb->fd);
    free(bbdb);
  }
}

#ifdef BBDB_WRITE
/* Opens a new bbdb file */
bbdb_t * bbdb_new(
    char *path,
    int cachesize)
{
  assert(path);
  int rc;
  struct bbdb_t *bbdb = NULL;

  /* Allocate the main structure and initialize */
  bbdb = malloc(sizeof(bbdb_t));
  if (!bbdb) {
    bbdb_warn("Cannot allocate memory");
    goto err;
  }
  /* Initialize */
  memset(bbdb->path, 0, sizeof(bbdb->path));
  bbdb->fd = -1;
  bbdb->size = 0;
  bbdb->magic = 0;
  bbdb->revelation = -1;
  bbdb->map = NULL;
  bbdb->root = NULL;
  bbdb->rootindex = NULL;
  bbdb->sparse = NULL;
  bbdb->sparseindex = NULL;
  bbdb->crypto = NULL;
  bbdb->cryptindex = NULL;
  bbdb->treesize = NULL;
  bbdb->pgindx = NULL;
  bbdb->pgindxindex = NULL;
  bbdb->license = NULL;
  bbdb->licenseindex = NULL;
  bbdb->lru = NULL;

  strncpy(bbdb->path, path, sizeof(bbdb->path)-1);

  /* Open the file */
  bbdb->fd  = open(bbdb->path, O_RDWR|O_TRUNC|O_CREAT|O_EXCL, 0640);
  if (bbdb->fd < 0) {
    bbdb_warn("Cannot create new file %s", path);
    goto err;
  }

  /* Allocate the appropriate chunk size to the file */
  if (fallocate(bbdb->fd, 0, 0, BBDB_CHUNKSIZE) < 0) {
    bbdb_warn("Cannot create a chunk from bbdb file %s", bbdb->path);
    goto err;
  }

  /* Write the magic to the file */
  bbdb->magic = BBDB_MAGIC;
  if (write(bbdb->fd, &bbdb->magic, sizeof(BBDB_MAGIC)) < sizeof(BBDB_MAGIC)) {
    bbdb_warn("Could not write magic to file %s", bbdb->path);
    goto err;
  }

  /* Revelation is just the unix epoch for now */
  bbdb->revelation = time(NULL);
  if (write(bbdb->fd, &bbdb->revelation, sizeof(bbdb->revelation)) < sizeof(bbdb->revelation)) {
    bbdb_warn("Could not write revelation to file %s", bbdb->path);
    goto err;
  }

  /* Map the remainder of the file into memory */
  bbdb->map = mmap(NULL, BBDB_CHUNKSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, bbdb->fd, 0);
  if (bbdb->map == MAP_FAILED) {
    bbdb_warn("Could not map file %s", bbdb->path);
    goto err;
  }
  bbdb->rootindex = (uint64_t *)(bbdb->map+12); 
  bbdb->sparseindex = (uint64_t *)(bbdb->map+20); 
  bbdb->cryptindex = (uint64_t *)(bbdb->map+28); 
  bbdb->treesize = (uint64_t *)(bbdb->map+36); 
  bbdb->pgindxindex = (uint64_t *)(bbdb->map+44); 
  bbdb->licenseindex = (uint64_t *)(bbdb->map+56); 
  bbdb->numrecs = (int64_t *)(bbdb->map+64); 
  *bbdb->rootindex = 1;
  *bbdb->sparseindex = 0;
  *bbdb->pgindxindex = 0;
  *bbdb->licenseindex = 0;
  *bbdb->cryptindex = 0;
  *bbdb->treesize = 0;
  *bbdb->numrecs = 0;

  /* Initialize the root node */
  bbdb->root = bbdb_external_node_init(bbdb, 0);

  /* Initialize the LRU */
  bbdb->lru = lru_new(cachesize, (cachesize + cachesize/2));
  bbdb->lru_hits = 0;
  bbdb->lru_misses = 0; 
  return bbdb;

err:
  if (bbdb) {
    if (bbdb->map)
      munmap(bbdb->map, BBDB_CHUNKSIZE);
    if (bbdb->lru)
      lru_destroy(bbdb->lru);
    close(bbdb->fd);
    free(bbdb);
  }
  return NULL;
}
#endif

#ifdef BBDB_WRITE
/* Once building the tree is finished, the following operations occur
 * 1. An auxillary index is built.
 * 2. A license is added.
 * 3. Shasums of all the btree and auxillary index pages are generated.
 * 4. A signage on the shasums, and license page is computed and applied.
 * 5. A page index is built.
 * 6. The file is truncated to its true size.
 * 7. A validation of the database is performed.
 * 7. The new size in bytes is returned
 */
uint64_t bbdb_commit(bbdb_t *bbdb,
    bbdb_license_t *li,
    EVP_PKEY *key,
    X509 *cert,
    X509_STORE *trustdb)
{
  char *map = NULL;
  bbdb_build_sparse_table(bbdb);
  bbdb_build_license_table(bbdb, li);
  bbdb_build_crypto_table(bbdb, key, cert, trustdb);
  bbdb_build_pgindx_table(bbdb);

  /* Now truncate to our true size. */
  map = mremap(bbdb->map, BBDB_CHUNKSIZE, BBDB_PAGESIZE * (bbdb->size+1), 0);
  if (map == MAP_FAILED)
    err(EXIT_FAILURE, "Could not shrink mapping, commit failed");
  bbdb->map = map;
  if (ftruncate(bbdb->fd,  BBDB_PAGESIZE * (bbdb->size+1)) < 0)
    err(EXIT_FAILURE, "Could not shrink file, commit failed");

  /* Validate */
  if (!bbdb_verify_crypto_table(bbdb, trustdb))
    err(EXIT_FAILURE, "Validation of database failed");

  if (msync(bbdb->map, BBDB_PAGESIZE * bbdb->size, MS_SYNC) < 0)
    err(EXIT_FAILURE, "Could not commit changes to database");

  return (BBDB_PAGESIZE * bbdb->size); 
}
#endif

#ifdef BBDB_WRITE
enum verdict bbdb_insert(
    bbdb_t *bbdb,
    uint32_t key,
    enum verdict verdict)
{
  assert(bbdb);
  assert(verdict > NONE && verdict <= ERROR);

  int pos;
  enum verdict oldv;
  bbdb_ex_node_t *ex = bbdb->root;
  bbdb_in_node_t *in = bbdb_internal(ex, ex->offset);


  while (1) {
    in = bbdb_find_internal(ex, key);
    /* Check if it was the key, or just the closest match */
    if (in->key != key) {
      pos = key > in->key ? 1 : 0;
      /* If a external node exists, descend. */
      if (in->external_nodes[pos] != 0)
        ex = bbdb_external(bbdb, in->external_nodes[pos]);
      else {
        /* Insert the node here */
        if (bbdb_insert_internal(ex, in, key, verdict, 0, 0) == SPLIT) {
          bbdb_split(bbdb, ex, key);
        }
        (*bbdb->numrecs)++;
        return NONE;
      }
      continue;
    }
    /* Key does not exist / node is empty */
    else if (in->verdict == NONE) {
      /* Insert the node here */
      if (bbdb_insert_internal(ex, in, key, verdict, 0, 0) != NONE) 
        bbdb_err(EXIT_FAILURE, "Something terrible occurred");
      (*bbdb->numrecs)++;
      return NONE;
    }
    /* Key matched */
    else {
      /* Allow overwrite of verdict if its greater than the old entry */
      oldv = in->verdict;
      if (verdict > in->verdict) {
        in->verdict = verdict;
        return oldv;
      }
      else {
        return DUPLICATE;
      }
    }
  }
}
#endif

#ifdef BBDB_WRITE
bbdb_license_t * bbdb_license_new(
    void)
{
  bbdb_license_t *li = malloc(sizeof(bbdb_license_t));
  if (!li)
    return NULL;

  memset(li, 0, sizeof(bbdb_license_t));
  return li;
}

void bbdb_license_destroy(
    bbdb_license_t *li)
{
  if (!li)
    return;

  free(li);
}

void bbdb_license_set_flow(
    bbdb_license_t *li,
    uint16_t flow)
{
  assert(li);
  flow &= (LICENSE_MODE_IN|LICENSE_MODE_OUT|LICENSE_MODE_FWDIN|LICENSE_MODE_FWDOUT);
    return;

  li->mode |= flow;
}

void bbdb_license_set_expiry(
    bbdb_license_t *li,
    uint32_t time)
{
  assert(li);
  if (time == 0)
    li->mode &= ~LICENSE_MODE_TIME;
  else
    li->mode |= LICENSE_MODE_TIME;
  li->expiry = time;
}

void bbdb_license_set_id(
    bbdb_license_t *li,
    const char id[64])
{
  assert(li);

  if (id[0] == 0) {
    memset(li->identification, 0, 64);
    li->mode &= ~LICENSE_MODE_ID;
  }
  else {
    strncpy(li->identification, id, 63);
    li->mode |= LICENSE_MODE_ID;
  }
}

int bbdb_license_add_ip(
    bbdb_license_t *li,
    const char *ip,
    uint8_t mask)
{
    assert(li);
    assert(ip);

    assert(mask > 7 && mask <= 32);

    uint32_t ipa = 0;
    uint32_t maska = 1 << (32-mask);
    maska = ~maska;
    if (inet_pton(AF_INET, ip, &ipa) != 0)
      return 0;

    if (li->ipsize >= LICENSE_MAX_IPS)
      return -1;

    li->ips[li->ipsize].addr = ipa;
    li->ips[li->ipsize].mask = maska;
    li->ipsize++;
    li->mode |= LICENSE_MODE_IP|LICENSE_MODE_IN; 
    return 1;   
}
#endif

/* Performs a binary search for the closest matching internal node */
static bbdb_in_node_t * bbdb_find_internal(
   bbdb_ex_node_t *ex,
   int key)
{
  assert(ex);

  int first, middle, last;
  bbdb_in_node_t *in = NULL;
  first = 0;
  last = ex->size-1;
  middle = ex->size/2;

  if (ex->size <= 0)
    return &ex->keys[0];

  while (first <= last) {
    in = &ex->keys[middle];

    if (key == in->key && in->verdict != NONE)
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


uint64_t bbdb_sparse_search(
    bbdb_t *bbdb,
    uint32_t key)
{
  int first, middle, last;
  bbdb_sparse_entry_t *en = NULL;

  first = 0;
  last = (*bbdb->treesize)-1;
  middle = (*bbdb->treesize) / 2;
  en = bbdb_get_sparse_table(bbdb);

  while (first <= last) {
    if (key == en[middle].key)
      return en[middle].index;

    if (key > en[middle].key)
      first = middle+1;  
    else
      last = middle - 1;

    middle = (first + last) / 2;
  }

  if (last >= (*bbdb->treesize))
    return en[(*bbdb->treesize)-1].index;
  else if (first < 0)
    return en[0].index;
  return en[middle].index;
}


enum verdict bbdb_verdict(
    bbdb_t *bbdb,
    uint32_t candidate)
{
  assert(bbdb);

  int pos;
  bbdb_ex_node_t *ex = bbdb->root;
  bbdb_in_node_t *in = NULL;
  bbdb_sparse_entry_t *st = NULL;
  uint64_t idx;
  enum verdict v;

  v = lru_search(bbdb->lru, candidate);
  /* Look in the cache */
  if (v != NONE) {
    bbdb->lru_hits++;
    return v;
  }
  bbdb->lru_misses++;
  if ((bbdb->lru_misses % BBDB_MISS_FLUSH) == 0) {
    if (madvise(bbdb->root, (*bbdb->treesize) * BBDB_PAGESIZE, MADV_DONTNEED) < 0)
      if (errno != ENOMEM)
        bbdb_warn("Couldn't free btree mapping");
  }

  /* Try the auxillary index if it exists */
  st = bbdb_get_sparse_table(bbdb);
  if (st) {
    idx = bbdb_sparse_search(bbdb, candidate);
    ex = bbdb_external(bbdb, idx);
    in = bbdb_find_internal(ex, candidate);

    if (in->verdict != NONE && in->key == candidate) {
      lru_insert(bbdb->lru, candidate, in->verdict);
      return in->verdict;
    }
    /* In a special case, the value can exist in the block above cause its the parent key */
    if (ex->upidx != 0) {
      ex = bbdb_external(bbdb, ex->upidx);
      in = bbdb_find_internal(ex, candidate);
      if (in->verdict != NONE && in->key == candidate) {
        lru_insert(bbdb->lru, candidate, in->verdict);
        return in->verdict;
      }
      else {
        lru_insert(bbdb->lru, candidate, DEFAULT);
        return DEFAULT;
      }
    }
    else {
      lru_insert(bbdb->lru, candidate, DEFAULT);
      return DEFAULT;
    }
  }

  else {
    while (1) {
      in = bbdb_find_internal(ex, candidate);
      /* Check if it was the key, or just the closest match */
      if (in->key != candidate) {
        pos = candidate > in->key ? 1 : 0;
        /* If a external node exists, descend. */
        if (in->external_nodes[pos] == 0) {
          lru_insert(bbdb->lru, candidate, DEFAULT);
          return DEFAULT;
        }
        ex = bbdb_external(bbdb, in->external_nodes[pos]);
        continue;
      }
      /* Key does not exist */
      else if (in->verdict == NONE) {
        lru_insert(bbdb->lru, candidate, DEFAULT);
        return DEFAULT;
      }
      /* Key matched */
      else {
        lru_insert(bbdb->lru, candidate, in->verdict);
        return in->verdict;
      }
    }
  }
}










static X509 * get_cert(const char *path)
{
  X509 *cert = NULL;

  FILE *fd = fopen(path, "r");
  char certbuf[16384];
  int sz;

  if (!fd)
    err(EXIT_FAILURE, "cannot open cert file");

  cert = PEM_read_X509(fd, NULL, NULL, NULL);
  if (!cert) {
    fseek(fd, 0, 0);
    cert = d2i_X509_fp(fd, &cert);
  }
  if (!cert) 
    errx(EXIT_FAILURE, "Certificate file is not in DER or PEM format\n");

  fclose(fd);
  return cert;
  
}

static X509_STORE * get_root(void)
{
  X509 *cert = NULL;
  X509_STORE *trustdb = NULL;

  const unsigned long long sz = (const unsigned long long)&_binary_root_der_size;
  const unsigned char *buf = _binary_root_der_start; 
  cert = d2i_X509(NULL, &buf, sz);
  if (!cert)
    err(EXIT_FAILURE, "Root key cannot be retrieved");

  trustdb = X509_STORE_new();  
  if (!trustdb)
    err(EXIT_FAILURE, "Cannot initialize trustdb");
  if (!X509_STORE_add_cert(trustdb, cert))
    err(EXIT_FAILURE, "Cannot use trustdb");

  return trustdb;
}

static EVP_PKEY * get_key(const char *path)
{
  FILE *fd = fopen(path, "r");
  EVP_PKEY *key = NULL;

  if (!fd)
    err(EXIT_FAILURE, "cannot read private key");

  if (PEM_read_PrivateKey(fd, &key, NULL, NULL) == NULL)
    err(EXIT_FAILURE, "private key file is not a private key");

  fclose(fd);
  return key;
}


#define TOTALKEYS 60000
int main() {
  OPENSSL_config(NULL);
  enum verdict verdict;
  bbdb_t *bbdb = NULL;
  int i;
  struct timeval then, now;
  X509_STORE *trustdb = NULL;
  X509 *cert = NULL;
  EVP_PKEY * key = NULL;

  srand(1);

  bbdb = bbdb_new("test.bbd", 10240);
  if (!bbdb) {
    printf("Fail\n");
    unlink("test.bbd");
    exit(1);
  }

  printf("Generating ips to insert..\n");
  int k;
  for (i=0; i < TOTALKEYS; i++) {
    k = rand();
    if ((i % 999999) == 0)
      printf("Inserting key number %lu\n", i);
    bbdb_insert(bbdb, k, DROP);
  }

  /* Adding license */
  bbdb_license_t *li = bbdb_license_new();
  bbdb_license_set_flow(li, LICENSE_MODE_IN|LICENSE_MODE_OUT);
  bbdb_license_set_id(li, "3603A0B4-4F93-A043-AAAA-A4D3D2749355");
  bbdb_license_set_expiry(li, time(NULL) + (30*86400));
  if (bbdb_license_add_ip(li, "108.61.177.95", 32))
    err(EXIT_FAILURE, "Couldn't add IP");

  /* Get certs for crypto */
  cert = get_cert("./root.der");
  trustdb = get_root();
  key = get_key("key.pem");

  /* Commit the database */
  printf("Committing..\n");
  bbdb_commit(bbdb, li, key, cert, trustdb);
  bbdb_license_destroy(li);
  bbdb_close(bbdb);

  printf("Loading..\n");
  bbdb = bbdb_load("test.bbd", 10240, trustdb);
  if (!bbdb)
    exit(0);
  printf("Loaded\n");

  printf("Tree size in pages: %llu\n", *bbdb->treesize);
  printf("Number of records: %llu\n", *bbdb->numrecs);
  printf("Sparse size in pages: %llu\n", bbdb->sparse->size);
  printf("checking inserted entries\n");

  gettimeofday(&then,NULL);
  //while (1) {
    srand(1);
    for (i=0; i < TOTALKEYS; i++) {
      k = rand();
      verdict = bbdb_verdict(bbdb, k);
      if (verdict != 2) {
        printf("%d %lu: %d\n",i, k, verdict);
      }
    }
    if (verdict != 2) {
      printf("%lu: %d\n",k, verdict);
    }

  //}

  gettimeofday(&now,NULL);
  printf("Then: %u.%.6u\n", then.tv_sec, then.tv_usec);
  printf("Now:  %u.%.6u\n", now.tv_sec, now.tv_usec);

  bbdb_close(bbdb);
  bbdb = NULL;

  exit(0);
}
