#ifndef _PAGE_H
#define _PAGE_H

#include "config.h"

/* This value dictates the number of btree external nodes and the 
 *shape of database! Choose carefully.. */
#define PAGESIZE 4096

/* The number of pages to pre-allocate once we reach the file size */
#define BBDB_CHUNKSIZE 64 

/* File magic used to sanity check definitions on disk */
/* Magic format:              0xBBDBBBDBBBDBIIVV
 * Where II is the identifier and VV is the versions
 */
#define BBDB_MAGIC_HDR        0xBBDBBBDBBBDB0000
#define BBDB_MAGIC_INDEX      0xBBDBBBDBBBDB0001
#define BBDB_MAGIC_CRYPTO     0xBBDBBBDBBBDB0002
#define BBDB_MAGIC_LICENSE    0xBBDBBBDBBBDB0003
#define BBDB_MAGIC_EXNODE     0xBBDBBBDBBBDB0004
#define BBDB_MAGIC_FREE       0xBBDBBBDBBBDB0005

#define BBDB_MAGIC_HDR_OFFSET 0
#define INDEX_HDR_OFFSET      24
#define CRYPTO_HDR_OFFSET     48
#define LICENSE_HDR_OFFSET    56
#define BLITZ_HDR_OFFSET      64
#define BBDB_HDR_OFFSET       88

#define CHECK_PAGE(page) \
  { \
    assert(page && (page->magic & BBDB_MAGIC_HDR) == BBDB_MAGIC_HDR); \
  }

#define DATALEN (PAGESIZE-SHA256_DIGEST_LENGTH-16)
typedef struct pagemap {
  int fd;
  int64_t size;
  int64_t capacity;
  size_t filesize;
  bool ro;
  void *map;
} pagemap_t;

typedef struct page {
  uint64_t magic;
  /* This number represents the numeric position of the page type */
  int64_t index;
  /* The shasum for this page */
  uint8_t checksum[SHA256_DIGEST_LENGTH];
  uint8_t data[DATALEN];
} page_t;

static inline void * page_get_data(
    page_t *page)
{
  CHECK_PAGE(page);
  return page->data;
}

static inline uint64_t page_get_magic(
    page_t *page)
{
  CHECK_PAGE(page);
  return page->magic;
}

static inline void page_set_magic(
    page_t *page,
    uint64_t magic)
{
  assert(page);
  page->magic = magic;
}

static inline uint8_t * page_get_checksum(
    page_t *page)
{
  CHECK_PAGE(page);
  return page->checksum;
}

static inline int64_t page_get_index(
    page_t *page)
{
  CHECK_PAGE(page);
  return page->index;
}

static inline void page_set_index(
    page_t *page,
    int64_t index)
{
  CHECK_PAGE(page);
  assert(index >= 0);
  page->index = index;
}

static inline void increment_pagemap_size(
    pagemap_t *pagemap)
{
  /* Make this an atopic increment? */
  pagemap->size++;
}

static inline int64_t page_get_offset(
    pagemap_t *pagemap,
    page_t *page)
{
  int64_t pg;
  pg = (void *)page - pagemap->map;
  assert(page >= 0);
  return (pg / PAGESIZE);
}

static inline int64_t page_get_index_of(
    void *data)
{
  assert(data);

  page_t *page = data - offsetof(page_t, data);
  return page->index;
}

static inline int64_t page_get_magic_of(
    void *data)
{
  assert(data);

  page_t *page = data - offsetof(page_t, data);
  return page->magic;
}


pagemap_t * pagemap_map(int fd);
void pagemap_destroy(pagemap_t *map);
page_t * page_get(pagemap_t *map, int64_t pageno);
page_t * page_init(pagemap_t *map, uint64_t magic);
void page_wipe(page_t *page);
int page_set_checksum(page_t *page);
int pagemap_extend(pagemap_t *pagemap);
void * page_get_data_of(pagemap_t *pagemap, int64_t offset, uint64_t magic);
pagemap_t * pagemap_new(int fd);
pagemap_t * pagemap_open(int fd);
int pagemap_close(pagemap_t *pagemap);
int pagemap_quiesce_pages(pagemap_t *pagemap);
int page_validate_checksum(page_t *page);
#undef CHECK_PAGE
#endif
