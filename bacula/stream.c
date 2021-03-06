#include "stream.h"
#include "volume.h"
#include "base64.h"
#include "label.h"
#include <sysexits.h>

#define MAX_STREAMS 32

#define CHECK_STREAM_PARAMS() \
  if (!rtype) { \
    warn("No rtype supplied"); \
    return 0; \
  } \
  if (!vol) { \
    warn("No vol supplied"); \
    return 0; \
  }

static int h_nonestream(volume_t *vol, stream_t *rtype);
static int h_unixattrstream(volume_t *vol, stream_t *rtype);
static int h_filedatastream(volume_t *vol, stream_t *rtype);
static int h_md5stream(volume_t *vol, stream_t *rtype);
static int h_gzipstream(volume_t *vol, stream_t *rtype);
static int h_shastream(volume_t *vol, stream_t *rtype);

/* Global handler for all stream */
static struct {
  int (*callback)(volume_t *vol, stream_t *rtype);
} stream_handler[MAX_STREAMS];


/* Initialize stream global */
void stream_init(
    void)
{
  memset(stream_handler, 0, sizeof(stream_handler));

  stream_handler[STREAM_TYPE_NONE].callback = h_nonestream;
  stream_handler[STREAM_UNIX_ATTRIBUTES].callback = h_unixattrstream;
  stream_handler[STREAM_FILE_DATA].callback = h_filedatastream;
  stream_handler[STREAM_GZIP_DATA].callback = h_gzipstream;
  stream_handler[STREAM_MD5_DIGEST].callback = h_md5stream;
  stream_handler[STREAM_SHA1_DIGEST].callback = h_shastream;
}

/* Attempt to retrieve a complete stream type, including continuations */
int stream_read(
    volume_t *vol,
    stream_t *rtype)
{
  /* IF this is not initialized, do it */
  if (!stream_handler[STREAM_TYPE_NONE].callback)
    stream_init();

  record_t *rec = &vol->record;
  block_t *block = &vol->block;

  int continuation=0;
  int lastfi;
  int lastvolid;
  int lastvoltime;
  int remaining;
  void *p;
  int end = 0;
  int cnt=0;
  int rc;

  if (!rec || !block) {
    warn("Invalid record");
    goto fail;
  }

  if (rtype->data) 
     free(rtype->data);

  memset(rtype, 0, sizeof(stream_t));
  rtype->type = -1;

  while (1) {
    if ((rc = record_get(vol)) < 0) {
      warnx("Unable to retrieve valid record");
      end = 1;
      goto fail;
    }

    if (rc == 0) {
      goto fail;
    }

    /* Streams have no interest in volume labels. */
    if (rec->fileindex < 0) {
      block->offset += rec->length;
      continue;
    }

    /* Check we have a handler for the stream */
    if (rec->stream < 0) {
      /* Continuation record */
      rec->stream = -rec->stream;
    }
    rec->stream & 0x7FF;

    /* If the record length is greater than the block len + offset
     * this must be a continuation record, we need more bytes */
    /* We set the stream type on the first example of this stream type
     * that we find */
    remaining = block->length - block->offset;

    if (rec->length > remaining) {
      if (rtype->type == -1) {
        rtype->type = rec->stream;
      }

      if (rtype->type != rec->stream) {
        /* whoops, continuation looks to be the wrong stream type */
        /* We ignore this type */
        block->offset += remaining;
        continue;
      }

      rtype->data = realloc(rtype->data, rtype->length + remaining); 
      if (!rtype->data) {
        warn("Couldn't allocate %d bytes memory extra %d bytes", rtype->length + remaining);
        goto fail;
      }

      p = rtype->data + rtype->length;
      rtype->length += remaining;
      memcpy(p, block->data+block->offset, remaining);
      block->offset += remaining;
      continue;
    }
    else {
      if (rtype->type == -1) {
        rtype->type = rec->stream;
      }

      rtype->data = realloc(rtype->data, rtype->length + rec->length);
      if (!rtype->data) {
        warn("Couldn't allocate %d bytes memory 2", rtype->length + rec->length);
        goto fail;
      }

      p = rtype->data + rtype->length;
      rtype->length += rec->length;
      memcpy(p, block->data+block->offset, rec->length);
    }
    
    if (rec->stream > MAX_STREAMS || rec->stream < 0) {
      warnx("Reported stream is an invalid stream number (%d)", rec->stream);
      goto fail;
    }
    /* we got told we were contining, but the continuation record is for anoher
     * stream type */
    if (continuation && rtype->type != rec->stream) {
      warn("Received a continuation for a different stream type!\n");
      goto fail;
    }

    if (stream_handler[rec->stream].callback) {
      if (!stream_handler[rec->stream].callback(vol, rtype)) {
        warnx("stream: %d cont %d len %d rem %d", rec->stream, continuation, rtype->length, block->length - block->offset);
        goto fail;
      }
    }
    else {
      warnx("No stream handler for stream type %d", rec->stream);
      goto fail;
    }
    
    break;
  }

  block->offset = block->offset + rec->length;
  return 1;

fail:
  if (vol && rec) {
    block->offset += rec->length;
  }
  if (rtype->data) {
    free(rtype->data);
    memset(rtype, 0, sizeof(stream_t));
  }

  return -end;
}


/********* Stream handling functions ************/
static int h_nonestream(
    volume_t *vol,
    stream_t *rtype)
{
  CHECK_STREAM_PARAMS();
  rtype->type = STREAM_TYPE_NONE;

  return 1;
}



static int h_shastream(
    volume_t *vol,
    stream_t *rtype)
{
  /* No need for manipulation here */
  rtype->type = STREAM_SHA1_DIGEST;
  return 1;
}


static int h_md5stream(
    volume_t *vol,
    stream_t *rtype)
{
  /* No need for manipulation here */
  rtype->type = STREAM_MD5_DIGEST;
  return 1;
}


static int h_filedatastream(
    volume_t *vol,
    stream_t *rtype)
{
    CHECK_STREAM_PARAMS();
    /* There is no 'handling' of this data type */
    rtype->type = STREAM_FILE_DATA;
    return 1;
}



static int h_gzipstream(
    volume_t *vol,
    stream_t *rtype)
{
  CHECK_STREAM_PARAMS();
  /* There is no 'handling' of this data type */
  rtype->type = STREAM_GZIP_DATA;
  return 1;
}



static int h_unixattrstream(
    volume_t *vol,
    stream_t *rtype)
{
  CHECK_STREAM_PARAMS();

  void *data;
  int rc;
  int64_t i;
  char *attr;
  char *p;
  char binbuf[128];
  struct stat *st = &rtype->stream.unixattr.stat;

  data = rtype->data;
  if (!data) {
    warn("No data %p", data);
    return 0;
  }

  rtype->type = STREAM_UNIX_ATTRIBUTES;
  if (sscanf(data, "%d %d %256s",
      &rtype->stream.unixattr.fileindex,
      &rtype->stream.unixattr.type, 
      rtype->stream.unixattr.name) != 3) {
    warnx("Cannot read file attribute stream: %s", data ? data : "(nil)");
    return 0;
  }
  if (rtype->stream.unixattr.fileindex != vol->record.fileindex) {
    errx("File %s reports stat file index %d and record fileindex %d!\n",
      rtype->stream.unixattr.name,
      rtype->stream.unixattr.fileindex,
      vol->record.fileindex);
  }

  data += strlen(data)+1;
  strncpy(rtype->stream.unixattr.attr, data, ATTR_MAX);

  return 1;
}
