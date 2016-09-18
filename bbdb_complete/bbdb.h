#ifndef BBDB_H
#define BBDB_H
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
#include <openssl/x509.h>

#include "config.h"

#define BBDB_CHUNKSIZE (314572800*3)
/* The maximum number of LRU entries there can be at once */
#define BBDB_LRU_MAX 1048576
/* Determines how often to flush to btree every time a lookup results in a miss */
/* The value set is the worst case equivalent of 50MiB */
#define BBDB_MISS_FLUSH 12800  

#define BBDB_RESERVE (100/BBDB_RESERVE_PC)

/* This is a temporary thing */
#include <err.h>
#define bbdb_warn(args...) warnx(args)
#define bbdb_err(exit_code, args...) err(exit_code, args)

/* Verification definitions */
#define BBDB_VERIFY_ALL       0
#define BBDB_VERIFY_SAMPLE    1
#define BBDB_VERIFY_SAMPLE_PC 15        /* Percentage of pages to sample in sample verify mode */
#define BBDB_VERIFY_THRESHOLD 367001600 /* Threshold to change verify modes */

/* This value dictates the number of external nodes and the shape of database! Choose carefully.. */
#define BBDB_PAGESIZE 4096

/* The amount of data as a percentile of the original page size to add on top of an entry */
#define BBDB_RESERVE_PC 20
#define BBDB_RESERVE (100/BBDB_RESERVE_PC)


/* File magic used to sanity check definitions on disk */
#define BBDB_MAGIC          0xBBDBBBDBBBDB0000
#define BBDG_MAGIC_PGINDX   0xBBDBBBDBBBDB0001
#define BBDB_MAGIC_NODE     0xBBDBBBDBBBDB0002
#define BBDB_MAGIC_VERIFY   0xBBDBBBDBBBDB0004
#define BBDB_MAGIC_LICENSE  0xBBDBBBDBBBDB0005


/* We always want to permit bbdb_ex_node_t to fit within one BBDB_PAGESIZE, so we knock some of the nodes off. */
#define NUMKEYS (((BBDB_PAGESIZE / sizeof(bbdb_in_node_t)) & 0xFFFFFFFE) - 2)

/* STRUCT DEFS GO HERE */

/* In the code if we hit a duplicate key during insert, we permit the keys verdict
 * to be overwritten if its greater than the verdict already set */
enum verdict {
  NONE,    /* refers to a node not being initialized */
  DEFAULT, /* what the calling programs default policy is */
  DROP,
  REJECT,
  ALLOW,
  SPLIT,  /* When we must split the external node */
  DUPLICATE, /* The key inserted already exists as a higher priority */
  ERROR,  /* When an error happens */
};

/* The page index defines the page number from the index number */
typedef struct bbdb_pgindx_table_t {
  uint64_t magic;
  int size;
} bbdb_pgindx_table_t;

typedef struct bbdb_pgindx_entry_t {
  int64_t page;
  int64_t index;
} bbdb_pgindx_entry_t;

/* Stores all the cryptographic hashes for each page */
typedef struct bbdb_crypto_table_t {
  uint64_t magic;
  int64_t size;
  /* The total number of pages available */
  int64_t capacity;
  uint32_t numrecs;
  /* The time by which the db becomes invalid */
  uint16_t certsize;
  uint16_t sigsz;
} bbdb_crypto_table_t;

/* The crypto entry used for validation */
typedef struct bbdb_crypto_entry_t {
  uint64_t index;
  char hash[32];
} bbdb_crypto_entry_t;

/* Restrict the software using any of the following modes */
/* No license restrictions */
#define LICENSE_MODE_NONE   0x00
/* Only work where the systems UUID matches the given UUID */
#define LICENSE_MODE_ID     0x01
/* Only check for a given list of IP networks */
#define LICENSE_MODE_IP     0x02
/* Enforce a expiry time */
#define LICENSE_MODE_TIME   0x04
/* Enforce softare to work only in certain directions */
#define LICENSE_MODE_IN     0x08
#define LICENSE_MODE_OUT    0x10
#define LICENSE_MODE_FWDIN  0x20
#define LICENSE_MODE_FWDOUT 0x40

typedef struct bbdb_ipnet_t {
  /* The IP address */
  uint32_t addr;
  /* Any network mask restrictions on the address */
  uint32_t mask; 
} bbdb_ipnet_t;


/* Max number of ips allowed */
#define LICENSE_MAX_IPS (sizeof(bbdb_ipnet_t) / (BBDB_PAGESIZE-36))

/* The license page */
typedef struct bbdb_license_t {
  uint64_t magic;
  int64_t size;
  int64_t capacity;
  /* Contains the license check mode */
  uint16_t mode;
  /* Typically stores the UUID */
  char identification[64];
  /* A timeout by which this database becomes invalid */
  uint32_t expiry;
  /* The number of IP addresses in the license */
  uint32_t ipsize;
  bbdb_ipnet_t ips[LICENSE_MAX_IPS];
} bbdb_license_t;

 /* An LRU node */
typedef struct bbdb_lru_node_t {
  /* The data is stored in a head/tail queue from the scope of the LRU */
  /* To be at the top height is to be the most frequently used.
   * To be at the bottom height is to be the least frequently used. */
  struct bbdb_lru_node_t *up;
  struct bbdb_lru_node_t *down;
  /* The data is stored in a linked list from the hashtable scope */
  struct bbdb_lru_node_t *right;
  /* The actual data we care about */
  uint32_t key;
  enum verdict verdict;
} bbdb_lru_node_t;

/* The main LRU structure */
typedef struct bbdb_lru_t {
  /* The maximum number of entries */
  int size;
  /* This is the size of the hash table typical 1.5 x size */
  int h_size;
  /* Contains the hash pointers */
  bbdb_lru_node_t **hash;
  /* Contains the raw node data */
  bbdb_lru_node_t *nodes;
  /* The top of the lru */
  bbdb_lru_node_t *top;
  /* The bottom of the LRU */
  bbdb_lru_node_t *bottom;
  /* The lock when contention is a problem */
  pthread_mutex_t lock;
} bbdb_lru_t;

/*The internal node representation */
typedef struct bbdb_in_node_t {
  /* The actual key value */
  uint32_t key;
  enum verdict verdict;
  /* Stores the index to the entries external nodes. Or {0,0} if a leaf. */
  int64_t external_nodes[2];
} bbdb_in_node_t;


/* The external node representation */
typedef struct bbdb_ex_node_t {
  uint64_t magic;
  /* If this is the root */
  uint32_t upidx;
  /* Where on the media this index lives */
  uint64_t index;
  /* The position of the lowest internal node */
  int32_t offset;
  /* The number of active keys in the index */
  int32_t size;
  /* The keys */
  /* A reserve key is given for child->parent key migration */
  bbdb_in_node_t keys[NUMKEYS+1];
} bbdb_ex_node_t;

/* The main structure */
typedef struct bbdb_t {
  /* Name of the file */
  char path[PATH_MAX];
  int fd;
  /* Actual size of the database -- in pages */
  int64_t size;
  uint64_t magic; 
  int32_t revelation;
  char *map;
  /* The size of the btree */
  int64_t *treesize;
  bbdb_pgindx_table_t *pgindx;
  /* Page offset where different page types lie */
  uint64_t *pgindxindex;
  uint64_t *rootindex;
  uint64_t *cryptindex;
  uint64_t *licenseindex;
  int64_t *numrecs;
  int64_t *pages;
  /* The top of the btree */
  bbdb_ex_node_t *root;

  /* LRU data */
  bbdb_lru_t *lru;
  uint64_t lru_hits;
  uint64_t lru_misses;
  uint64_t hits;
  uint64_t misses;

  /* Path to the license */
  bbdb_license_t *license;

  /* The crypto verification table */
  bbdb_crypto_table_t *crypto;  
} bbdb_t;

#ifdef BBDB_WRITE
bbdb_t * bbdb_new(char *path, int cachesize);
enum verdict bbdb_insert(bbdb_t *bbdb, uint32_t key, enum verdict verdict);
void bbdb_build_crypto_table(bbdb_t *bbdb, EVP_PKEY *key, X509 *cert, X509_STORE *trustdb);
#endif

bbdb_t * bbdb_load(char *path, int cachesize, X509_STORE *trustdb);
bbdb_lru_t * lru_new(int size, int hashsize);
void lru_destroy(bbdb_lru_t *lru);
enum verdict bbdb_verdict(bbdb_t *bbdb, uint32_t candidate);
enum verdict lru_search(bbdb_lru_t *lru, uint32_t key);
void lru_insert(bbdb_lru_t *lru, uint32_t key, enum verdict);
void lru_flush(bbdb_lru_t *lru);
#endif
