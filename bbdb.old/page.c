#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "config.h"
#include "page.h"
/*
bbdb_page_t * page_init(bbdb_pagemap_t *map, uint64_t magic);
int page_set_checksum(bbdb_page_t *page);
int page_quiesce_pages(bbdb_pagemap_t *map, off_t offset, int numpages);
*/


static int page_sanity(
    bbdb_page_t *page)
{
  int magic;
  magic = page->magic & BBDB_MAGIC;

  if (magic != BBDB_MAGIC) {
    errno = EINVAL;
    return 0;
  }

  if (page->index < 0) {
    errno = EINVAL;
    return 0;
  }

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

  if (mode & ~(O_RDWR))
    return 1;
  else
    return 0;
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

  if (lseek(fd, pos, SEEK_SET))
    goto oops;

  return sz;

oops:
  WARN("Unable to acquire file size");
  return -1;
}


/* Maps the file */
bbdb_pagemap_t * pagemap_map(
    int fd)
{
  assert(fd >= 0);
  bbdb_pagemap_t *pagemap = NULL;

  int error;
  int ro;
  size_t sz;
  void *map;
  int mode;
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

  /* Perform mapping */
  mode = ro ? PROT_READ : PROT_READ|PROT_WRITE;
  map = mmap(NULL, sz, mode, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED)
    goto fail;

  /* Allocate and initialize */
  pagemap = malloc(sizeof(bbdb_pagemap_t));
  if (!pagemap)
    goto fail;

  pagemap->filesize = sz;
  pagemap->size = sz / BBDB_PAGESIZE;
  pagemap->ro = ro;
  pagemap->map = map;

  return pagemap;

fail:
  error = errno;
  if (pagemap)
    free(pagemap);
  if (map != MAP_FAILED)
    munmap(map, sz);
  errno = error;
  return NULL;
}


/* Destroy a pagemap */
void pagemap_destroy(
    bbdb_pagemap_t *pagemap)
{
  assert(pagemap);

  munmap(pagemap->map, pagemap->filesize);

  if (pagemap)
    free(pagemap);
  return;
}

/* Fetch a page from the map */
bbdb_page_t * page_get(
    bbdb_pagemap_t *pagemap,
    int64_t pageno)
{
  assert(pagemap);
  assert(pagemap->map);
  assert(pageno >= 0);

  off_t pos;
  uint64_t magic;
  bbdb_page_t *page;

  if (pageno >= pagemap->size) {
    errno = EBADSLT;
    return NULL;
  }

  pos = pageno * BBDB_PAGESIZE;
  if (pos >= pagemap->filesize) {
    errno = ENOSPC;
    return NULL;
  }

  page = pagemap->map + pos;

  /* Check page validity */
  if (!page_sanity(page))
    return NULL;

  return page;
}


/* Formats a page such that it would pass basic sanity checks */
bbdb_page_t * page_init(
    bbdb_pagemap_t *map,
    uint64_t magic)
{
  assert(pagemap);
  assert(pagemap->map);

  int64_t nextpage;

  /* Determine the next page */
}



/* ######################################################################### */
int main ()
{
 int fd = open("./moo.txt", O_RDWR|O_CREAT);

 bbdb_pagemap_t *map = pagemap_map(fd);

 if (page_get(map, 1) == NULL)
   ERR(EXIT_FAILURE, "");
 pagemap_destroy(map);
}
