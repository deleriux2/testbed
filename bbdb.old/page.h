#ifndef _PAGE_H
#define _PAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <openssl/sha.h>

/* This value dictates the number of external nodes and the shape of database! Choose carefully.. */
#define BBDB_PAGESIZE 4096

/* This value is used when creating the initial sparse file the db lives in. We need to pre-allocate a large amount
 * of disk space as the basis for our database */
#define BBDB_CHUNKSIZE (314572800*3)

/* The amount of data as a percentile of the original page size to add on top of an entry */
#define BBDB_RESERVE_PC 20
#define BBDB_RESERVE (100/BBDB_RESERVE_PC)


/* File magic used to sanity check definitions on disk */
#define BBDB_MAGIC          0xBBDBBBDBBBDB0000
#define BBDG_MAGIC_PGINDX   0xBBDBBBDBBBDB0001
#define BBDB_MAGIC_NODE     0xBBDBBBDBBBDB0002
#define BBDB_MAGIC_VERIFY   0xBBDBBBDBBBDB0004
#define BBDB_MAGIC_LICENSE  0xBBDBBBDBBBDB0005

#define CHECK_PAGE(page) { assert(page && (page->magic & BBDB_MAGIC) == BBDB_MAGIC); }

typedef struct bbdb_pagemap {
  int fd;
  int64_t size;
  size_t filesize;
  bool ro;
  void *map;
} bbdb_pagemap_t;

typedef struct bbdb_page {
  uint64_t magic;
  /* This number represents the numeric position of the page type */
  int64_t index;
  /* The shasum for this page */
  uint8_t checksum[SHA256_DIGEST_LENGTH];
  uint8_t data[BBDB_PAGESIZE-SHA256_DIGEST_LENGTH-16];
} bbdb_page_t;

static inline void * page_get_data(
    bbdb_page_t *page)
{
  CHECK_PAGE(page);
  return page->data;
}

static inline uint64_t page_get_magic(
    bbdb_page_t *page)
{
  CHECK_PAGE(page);
  return page->magic;
}

static inline void page_set_magic(
    bbdb_page_t *page,
    uint64_t magic)
{
  CHECK_PAGE(page);
  page->magic = magic;
}

static inline uint8_t * page_get_checksum(
    bbdb_page_t *page)
{
  CHECK_PAGE(page);
  return page->checksum;
}

static inline int64_t page_get_index(
    bbdb_page_t *page)
{
  CHECK_PAGE(page);
  return page->index;
}

static inline void page_set_index(
    bbdb_page_t *page,
    int64_t index)
{
  CHECK_PAGE(page);
  assert(index > 0);
  page->index = index;
}

bbdb_pagemap_t * pagemap_map(int fd);
void pagemap_destroy(bbdb_pagemap_t *map);
bbdb_page_t * page_get(bbdb_pagemap_t *map, int64_t pageno);
bbdb_page_t * page_init(bbdb_pagemap_t *map, uint64_t magic);
int page_set_checksum(bbdb_page_t *page);
int page_quiesce_pages(bbdb_pagemap_t *map, off_t offset, int numpages);

#undef CHECK_PAGE
#endif
