#define _GNU_SOURCE
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <openssl/evp.h>

#include "config.h"
#include "page.h"

EVP_MD_CTX *evp = NULL;
const EVP_MD *dgst = NULL;

static int checksum_page(
   bbdb_page_t *page,
   unsigned char *result)
{
  assert(page);
  assert(result);

  if (!EVP_DigestInit_ex(evp, dgst, NULL)) {
    errno = EINVAL;
    return 0;
  }

  /* Sum the magic, index and data */
  if (!EVP_DigestUpdate(evp, &page->magic, sizeof(page->magic)))
    return 0;
  if (!EVP_DigestUpdate(evp, &page->index, sizeof(page->index)))
    return 0;
  if (!EVP_DigestUpdate(evp, &page->data, sizeof(BBDB_DATALEN)))
    return 0;
  if (!EVP_DigestFinal_ex(evp, result, NULL))
    return 0;
  return 1;
}

static void initialize_digests(
    void)
{
  if (!dgst || !evp) {
    dgst = EVP_sha256();
    evp = EVP_MD_CTX_create();
  }
}

static bbdb_page_t * fetch_page(
    bbdb_pagemap_t *pagemap,
    off_t pageno)
{
  assert(pagemap);
  assert(pagemap->map);
  assert(pageno >= 0);

  off_t pos;
  uint64_t magic;
  bbdb_page_t *page;

  if (pageno >= pagemap->capacity) {
    errno = EBADSLT;
    return NULL;
  }

  pos = pageno * BBDB_PAGESIZE;
  if (pos >= pagemap->filesize) {
    errno = ENOSPC;
    return NULL;
  }

  page = pagemap->map + pos;
  return page;
}

static int sync_pagemap(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  if (msync(pagemap->map, pagemap->filesize, MS_SYNC) < 0)
    return 0;
  return 1;
}

static int is_readonly(
    int fd)
{
  int mode;
  mode = fcntl(fd, F_GETFL, NULL);
  if (mode < 0) {
    WARN("Attempted to fetch file attributes unsuccessfully");
    return -1;
  }

  if ((mode & O_RDWR) == O_RDWR)
    return 0;
  else
    return 1;
}

static int map_pagemap(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);
  int flags;

  flags = is_readonly(pagemap->fd);
  if (flags < 0)
     goto fail;
  else if (flags)
    flags = PROT_READ;
  else
    flags = PROT_READ|PROT_WRITE;
  
  pagemap->map = mmap(NULL, pagemap->filesize, flags, MAP_SHARED,
                      pagemap->fd, BBDB_PAGESIZE);

  if (pagemap->map == MAP_FAILED) {
    pagemap->map = NULL;
    goto fail;
  }

  return 1;

fail:
  return 0;
}

static int read_pagemap_header(
     bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  struct iovec vecs[2];
  uint64_t magic;
  int fd = pagemap->fd;

  /* Assign vecs */
  vecs[0].iov_base = &magic;
  vecs[0].iov_len = sizeof(magic);

  vecs[1].iov_base = &pagemap->capacity;
  vecs[1].iov_len = sizeof(pagemap->capacity);

  if (preadv(fd, vecs, 2, BBDB_MAGIC_HDR_OFFSET) < 0)
    return 0;

  if (magic != BBDB_MAGIC_HDR) {
    errno  = EBADR;
    return 0;
  }

  return 1;
}

static int write_pagemap_header(
     bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  struct iovec vecs[2];
  uint64_t magic = BBDB_MAGIC_HDR;
  int fd = pagemap->fd;

  /* Assign vecs */
  vecs[0].iov_base = &magic;
  vecs[0].iov_len = sizeof(magic);

  vecs[1].iov_base = &pagemap->capacity;
  vecs[1].iov_len = sizeof(pagemap->capacity);

  if (pwritev(fd, vecs, 2, BBDB_MAGIC_HDR_OFFSET) < 0)
    return 0;

  return 1;
}

static int allocate_pages(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  if (fallocate(pagemap->fd, 0, 0, pagemap->filesize) < 0)
    return 0;

  return 1;
}

static int page_sanity(
    bbdb_page_t *page)
{
  uint64_t magic;
  magic = (page->magic & BBDB_MAGIC_HDR);

  if (magic != BBDB_MAGIC_HDR) {
    errno = EINVAL;
    return 0;
  }

  if (page->index < 0) {
    errno = EINVAL;
    return 0;
  }

  return 1;
}

static size_t get_filesize(
    int fd)
{
  off_t pos;
  off_t sz;
  pos = lseek(fd, 0, SEEK_CUR);
  if (pos < 0)
    goto oops;

  sz = lseek(fd, 0, SEEK_END);
  if (sz < 0)
    goto oops;

  if (lseek(fd, pos, SEEK_SET) < 0)
    goto oops;

  return sz;

oops:
  WARN("Unable to acquire file size");
  return -1;
}



/* Creates a new pagemap entry */
bbdb_pagemap_t * pagemap_new(
    int fd)
{
  assert(fd >= 0);

  bbdb_pagemap_t *pagemap = NULL;
  int error;

  /* Get file access mode */
  if (is_readonly(fd)) {
    errno = EROFS; 
    goto fail;
  }

  /* Create the pagemap entry */
  pagemap = malloc(sizeof(bbdb_pagemap_t));
  if (!pagemap)
    goto fail;
  pagemap->fd = fd;
  pagemap->ro = false;
  pagemap->size = 0;
  pagemap->filesize = BBDB_PAGESIZE*(BBDB_CHUNKSIZE+1);
  pagemap->capacity = 64;

  /* Build the header and file out */
  if (!allocate_pages(pagemap))
    goto fail;

  if (!write_pagemap_header(pagemap))
    goto fail;

  /* Map the page range */
  if (!map_pagemap(pagemap) < 0)
    goto fail;

  return pagemap;

fail:
  error = errno;
  if (pagemap)
    free(pagemap);

  errno = error;
  return NULL;
}



/* Maps the file */
bbdb_pagemap_t * pagemap_open(
    int fd)
{
  assert(fd >= 0);
  bbdb_pagemap_t *pagemap = NULL;

  int error;
  int ro;
  size_t sz;

  /* Get file access mode */
  ro = is_readonly(fd);
  sz = get_filesize(fd);

  if (ro < 0 || sz < 0)
    goto fail;

  /* Check file is page-aligned */
  if (sz % BBDB_PAGESIZE) {
    WARNX("The database file is not page-aligned. Database may have been corrupted during creation.");
    sleep(3);
  }

  /* Allocate and initialize */
  pagemap = malloc(sizeof(bbdb_pagemap_t));
  if (!pagemap)
    goto fail;

  pagemap->fd = fd;
  pagemap->ro = ro;
  pagemap->filesize = sz;
  pagemap->capacity = sz / BBDB_PAGESIZE;

  if (!read_pagemap_header(pagemap))
    goto fail;

  if (!map_pagemap(pagemap))
    goto fail;

  return pagemap;

fail:
  error = errno;
  if (pagemap) {
    if (pagemap->map != MAP_FAILED)
      munmap(pagemap, sz);
    free(pagemap);
  }
  errno = error;
  return NULL;
}



/* Destroy a pagemap */
void pagemap_destroy(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  if (pagemap->map != MAP_FAILED)
    munmap(pagemap->map, pagemap->filesize);

  if (pagemap)
    free(pagemap);
  return;
}



/* Safely closes a pagemap, writing headers to disk */
int pagemap_close(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  if (!write_pagemap_header(pagemap))
    return 0;

  if (!sync_pagemap(pagemap))
    return 0;

  pagemap_destroy(pagemap);
  return 1;
}



/* Fetch a page from the map */
bbdb_page_t * page_get(
    bbdb_pagemap_t *pagemap,
    int64_t pageno)
{
  if (pageno >= pagemap->size) {
    errno = EBADSLT;
    return NULL;
  }

  bbdb_page_t *page = fetch_page(pagemap, pageno);

  if (!page)
    return NULL;

  if (!page_sanity(page))
    return NULL;

  return page;
}



/* Formats a page such that it would pass basic sanity checks */
bbdb_page_t * page_init(
    bbdb_pagemap_t *pagemap,
    uint64_t magic)
{
  assert(pagemap);
  assert(pagemap->map);

  if (pagemap->ro) {
    errno = EROFS;
    return NULL;
  }

  int64_t nextpage = pagemap->size;
  bbdb_page_t *page = fetch_page(pagemap, nextpage);
  if (!page) {
    if (errno == EBADSLT) {
      if (!pagemap_extend(pagemap))
        return NULL;
      page = fetch_page(pagemap, nextpage);
    }
    else
      return NULL;
  }

  /* Refuse to overwrite an already allocated page */
  if ((page->magic & BBDB_MAGIC_HDR) == BBDB_MAGIC_HDR) {
    errno = EADDRINUSE;
    return NULL;
  }

  if (!page)
    return NULL;

  page_set_magic(page, magic);
  page_set_index(page, nextpage);

  increment_pagemap_size(pagemap);

  return page;
}



/* Drops the resident memory shared by these mappings from the caller */
int pagemap_quiesce_pages(
    bbdb_pagemap_t *pagemap, 
    off_t offset,
    size_t numpages)
{
  assert(pagemap);
  assert(offset >= 0);
  assert(numpages >= 0);

  bbdb_page_t *page;
  size_t len;

  /* This is basically a no-op */
  if (numpages == 0)
    return 1;

  if ((offset+numpages) >= pagemap->capacity)
    return 0;

  page = page_get(pagemap, offset);
  if (!page)
    return 0;

  len = numpages * BBDB_PAGESIZE;
  if (madvise(page, len, MADV_DONTNEED) < 0)
    return 0;

  return 1;
}



/* Extend the mapping */
int pagemap_extend(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  int64_t current_cap;
  off_t newsize;
  size_t chunk;

  chunk = BBDB_PAGESIZE * BBDB_CHUNKSIZE;
  newsize = 0;
  void *map;

  if (pagemap->ro) {
    errno = EROFS;
    return 0;
  }

  if (fallocate(pagemap->fd, 0, pagemap->filesize, chunk) < 0)
    return 0;

  newsize = get_filesize(pagemap->fd);
  if (newsize != pagemap->filesize + chunk) {
    errno = ENOSPC;
    return 0;
  }

  map = mremap(pagemap->map, pagemap->filesize, newsize, MREMAP_MAYMOVE);
  if (map == MAP_FAILED)
    return 0;

  if (!write_pagemap_header(pagemap))
    return 0;

  pagemap->map = map;
  pagemap->capacity += BBDB_CHUNKSIZE;
  pagemap->filesize = newsize;
  return 1;
}


/* Generates a checksum and stores the result to the page */
int page_set_checksum(
    bbdb_page_t *page)
{
  assert(page);

  uint8_t *checksum;

  initialize_digests();

  if (!page_sanity)
    return -1;

  checksum = page_get_checksum(page);
  if (!checksum_page(page, checksum))
    return -1;

  return 1;
}


/* Returns the data from a page, checks magic */
void * page_get_data_of(
    bbdb_pagemap_t *pagemap,
    int64_t offset,
    uint64_t magic)
{
  assert(pagemap);
  assert(offset >= 0);
  bbdb_page_t *page = page_get(pagemap, offset);
  if (page->magic != magic)
    return NULL;
  return (void *)page->data;
}



/* Checks the checksum against the stored sum on the page */
int page_validate_checksum(
    bbdb_page_t *page)
{
  assert(page);

  uint8_t checksum[SHA256_DIGEST_LENGTH];

  initialize_digests();

  if (!page_sanity)
    return -1;

  if (!checksum_page(page, checksum))
    return -1;

  if (memcmp(page->checksum, checksum, SHA256_DIGEST_LENGTH) != 0)
    return 0;

  return 1;
}
