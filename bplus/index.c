#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/uio.h>

#include "config.h"
#include "page.h"
#include "index.h"

static int walk_page_offsets(
    index_t *index)
{
  int i;
  int64_t *offsets;
  int64_t next_offset;
  index_page_t *ipage;

  offsets = calloc(index->size, sizeof(int64_t));
  if (!offsets)
    return 0;

  next_offset = index->offset;
  for (i=0; i < index->size; i++) {
    ipage = page_get_data_of(index->map, next_offset, BBDB_MAGIC_INDEX);
    if (!ipage)
      return 0;
    offsets[i] = page_get_index_of(ipage);
    next_offset = ipage->next;
  }
  index->index_page_offsets = offsets;
  return 1;
}

static int read_index_header(
    index_t *index)
{
  assert(index);
  assert(index->map);

  struct iovec vecs[3];
  int64_t pageno;
  int64_t size;
  int64_t capacity;
  int64_t record_num;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);
  vecs[1].iov_base = &size;
  vecs[1].iov_len = sizeof(size);
  vecs[2].iov_base = &record_num;
  vecs[2].iov_len = sizeof(record_num);

  if (preadv(index->map->fd, vecs, 3, INDEX_HDR_OFFSET) < 0)
    return 0;

  index->offset = pageno;
  index->size = size;
  index->record_num = record_num;

  return 1;
}

static int write_index_header(
    index_t *index)
{
  assert(index);
  assert(index->map);

  struct iovec vecs[3];
  int64_t pageno = index->offset;
  int64_t size = index->size;
  int64_t record_num = index->record_num;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);
  vecs[1].iov_base = &size;
  vecs[1].iov_len = sizeof(size);
  vecs[2].iov_base = &record_num;
  vecs[2].iov_len = sizeof(record_num);

  if (pwritev(index->map->fd, vecs, 3, INDEX_HDR_OFFSET) < 0)
    return 0;

  return 1;
}

static inline index_page_t * index_get_page(
    index_t *index,
    int64_t offset)
{
  assert(offset >= 0);

  page_t *page;
  index_page_t *ipage;
  int64_t pageno;
  if (offset >= index->size)
    return NULL;

  pageno = index->index_page_offsets[offset];
  page = page_get(index->map, pageno);
  if (!page)
    return NULL;
  ipage = page_get_data(page);

  return ipage;
}

static int64_t index_page_init(
    index_t *index)
{
  assert(index);

  page_t *page;
  index_page_t *ipage;
  index_page_t *ipage_prev;

  page = page_init(index->map, BBDB_MAGIC_INDEX);
  if (!page)
    return -1;

  int64_t nextpage = index->size;
  int64_t newsize = nextpage+1;
  int64_t *offsets;

  ipage = page_get_data(page);
  ipage->offset = nextpage;
  ipage->next = 0;

  /* Increase the index pages size in the main index to accomodate */
  offsets = realloc(index->index_page_offsets, sizeof(int64_t) * newsize);
  if (!offsets)
    return -1;
  offsets[nextpage] = page_get_index(page);

  /* Set previous page pointer */
  if (nextpage == 0)
    ipage->prev = 0;
  else
    ipage->prev = offsets[nextpage-1];


  /* Set the next page pointer in the penultimate page. */
  if (nextpage > 0) {
    ipage_prev = index_get_page(index, nextpage-1);
    ipage_prev->next = page_get_index(page);
  }

  index->size = newsize;
  index->index_page_offsets = offsets;
  return offsets[nextpage];
}



/* Creates a new page index */
index_t *index_new(
    pagemap_t *pagemap)
{
  assert(pagemap);

  int error;
  index_t *index;
  page_t *page;

  index = malloc(sizeof(index_t));
  if (!index) {
    error = errno;
    goto fail;
  }

  index->map = pagemap;
  index->size = 0;
  index->index_page_offsets = NULL;
  index->offset = index_page_init(index);
  if (index->offset < 0)
    goto fail;
  index->record_num = 0;

  if (!write_index_header(index)) {
    error = errno;
    goto fail;
  }

  return index;

fail:
  if (index && index->index_page_offsets)
    free(index->index_page_offsets);
  if (index)
    free(index);
  errno = error; 
  return NULL;
}



/* Opens an existing index */
index_t * index_open(
    pagemap_t *pagemap)
{
  assert(pagemap);

  int error;
  index_t *index;
  page_t *page;

  index = malloc(sizeof(index_t));
  if (!index) {
    error = errno;
    goto fail;
  }

  index->map = pagemap;
  index->size = 0;
  index->index_page_offsets = NULL;
  index->offset = -1;
  index->record_num = 0;

  if (!read_index_header(index)) {
    error = errno;
    goto fail;
  }

  if (!walk_page_offsets(index))
    goto fail;

  return index;

fail:
  if (index && index->index_page_offsets)
    free(index->index_page_offsets);
  if (index)
    free(index);
  errno = error; 
  return NULL;
}




/* Inserts an entry into the index table */
int index_add(
    index_t *index,
    page_t *page)
{
  assert(index);
  assert(page);

  index_page_t *ipage;
  index_record_t *rec;
  int64_t offset = page_get_offset(index->map, page);
  int64_t idx = page_get_index(page);
  int64_t index_pages_offset;
  int64_t index_records_offset;
  int64_t index_page_offset_number;

  index_page_offset_number = idx / INDEX_RECORDS_MAX;
  index_records_offset = idx % INDEX_RECORDS_MAX;

  if (index_page_offset_number == index->size) {
    if (!index_page_init(index))
      return 0;
  }

  index_pages_offset = index->index_page_offsets[idx / INDEX_RECORDS_MAX];
  ipage = page_get_data_of(index->map, index_pages_offset, BBDB_MAGIC_INDEX);
  if (!ipage)
    return 0;

  rec = &ipage->recs[index_records_offset];
  rec->magic = page->magic;
  rec->index = page->index;
  rec->page = offset;
  index->record_num++;

  return 1;
}



/* Safely closes the index */
void index_close(
    index_t *index)
{
  assert(index);

  if (!write_index_header(index))
    WARN("Unable to write index headers");
  
  if (index->index_page_offsets)
    free(index->index_page_offsets);
  free(index);
}


/* Search and return index */
int64_t index_lookup(
    index_t *index,
    int64_t offset)
{
  assert(index);
  assert(offset >= 0);

  int64_t pageno;
  int64_t recno;

  index_page_t *ipage;

  if (!index->index_page_offsets)
    return -1;

  assert((offset / INDEX_RECORDS_MAX) < index->size);

  pageno = index->index_page_offsets[offset / INDEX_RECORDS_MAX];
  recno = offset % INDEX_RECORDS_MAX;

  ipage = page_get_data_of(index->map, pageno, BBDB_MAGIC_INDEX);
  if (!ipage)
    return -1;

  if ((ipage->recs[recno].magic & BBDB_MAGIC_HDR) != BBDB_MAGIC_HDR)
    return -1;

  return ipage->recs[recno].page;
}



/* Removes the index entry for a given offset */
int64_t index_remove(
    index_t *index,
    page_t *page)
{
  assert(index);
  assert(page);


  int64_t pageno;
  int64_t recno;
  int64_t offset = page_get_index(page);

  index_page_t *ipage;

  if (!index->index_page_offsets)
    return -1;

  assert((offset / INDEX_RECORDS_MAX) < index->size);

  pageno = index->index_page_offsets[offset / INDEX_RECORDS_MAX];
  recno = offset % INDEX_RECORDS_MAX;

  ipage = page_get_data_of(index->map, pageno, BBDB_MAGIC_INDEX);
  if (!ipage)
    return -1;

  if ((ipage->recs[recno].magic & BBDB_MAGIC_HDR) != BBDB_MAGIC_HDR)
    return -1;

  ipage->recs[recno].page = -1;
  ipage->recs[recno].index = -1;
  ipage->recs[recno].magic = BBDB_MAGIC_FREE;
  return 1;
}
