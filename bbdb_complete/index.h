#ifndef _INDEX_H
#define _INDEX_H

#include "page.h"

#define BBDB_MAGIC_INDEX   0xBBDBBBDBBBDB0001

/* The page index defines the page number from the index number
 * This is used to allow fragmentation in the database and possibly
 * permit versionining going forward */

#define INDEX_HDR_OFFSET 16
#define INDEX_PAGE_SZ 44 

#define INDEX_RECORDS_MAX (\
    (BBDB_PAGESIZE - INDEX_PAGE_SZ)\
    / sizeof(index_record_t)\
  )

typedef struct index_record {
  /* The recorded magic for the page */
  uint64_t magic;
  /* The real page number associated with the entry */
  int64_t page;
  /* The 'virtual' page number associaed with the entry */
  int64_t index;
} index_record_t;

typedef struct index_page {
  /* When the index spans multiple pages, we
   * add another page and add another index. 
   */
  int64_t offset;
  /* The real page offset of the previous page */
  int64_t prev;
  /* The real page offset of the next page */
  int64_t next;
  index_record_t recs[INDEX_RECORDS_MAX];
} index_page_t;

typedef struct index {
  bbdb_pagemap_t *map;
  /* The real page number offset where the map begins */
  int64_t offset;
  /* The real page number this index is mapped to lives in the disk format */
  int64_t size;
  /* The total number of records stored in the index */
  int64_t record_num;
  /* Contains an array storing each pages offset */
  int64_t *index_page_offsets;
} index_t;

int index_add(index_t *index, bbdb_page_t *page);
index_t * index_new(bbdb_pagemap_t *pagemap);
void index_close(index_t *index);
index_t * index_open(bbdb_pagemap_t *pagemap);
int64_t index_lookup(index_t *index, int64_t offset);
#endif
