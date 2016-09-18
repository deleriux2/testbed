#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "page.h"
#include "index.h"

int main ()
{
  errno = 0;
  int fd = open("./moo.txt", O_RDWR|O_CREAT|O_TRUNC, 0660);
  int i;
  int rc;
  bbdb_pagemap_t *map;
  bbdb_page_t *page;
  WARN("open");

  map = pagemap_new(fd);
  WARN("pagemap_new");
  pagemap_close(map);
  WARN("pagemap_close");

  map = pagemap_open(fd);
  WARN("pagemap_open");

  for (i=0; i < 200; i++) {
    page = page_init(map, BBDB_MAGIC_HDR);
    if (!page)
      ERR(EXIT_FAILURE, "page_init");
  }  

  if (!page_get(map, 0))
    ERR(EXIT_FAILURE, "page_get, 0");

  pagemap_quiesce_pages(map, 0, 1);
  WARN("pagemap_quiesce_pages");

  if (!page_set_checksum(page)) {
    WARNX("page_set_checksum failed");
  }
  else {
    WARNX("page_set_checksum succeeded");
  }

  if (!page_validate_checksum(page)) {
    WARNX("page_validate_checksum failed");
  }
  else {
    WARNX("page_validate_checksum succeeded");
  }

  /* Index tests */
  index_t *index = index_new(map);
  WARN("index_new");
  for (i=0; i < 200; i++) {
    index_add(index, page_get(map, i));
  }

  index_close(index);
  WARN("index_close");

  index_open(map);
  WARN("index_open");

  for (i=0; i < 210; i++) {
    if ((rc = index_lookup(index, i)) < 0)
      printf("lookup failed %d\n", i);
  }

  pagemap_close(map);
  WARN("pagemap_close");
}
