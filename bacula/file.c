#include "file.h"
#include "base64.h"
#include <string.h>
#include <limits.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#define DEBUFSZ 10*1024*1024

#define FT_LNKSAVED   1               /* hard link to file already saved */
#define FT_REGE       2               /* Regular file but empty */
#define FT_REG        3               /* Regular file */
#define FT_LNK        4               /* Soft Link */
#define FT_DIREND     5               /* Directory at end (saved) */
#define FT_SPEC       6               /* Special file -- chr, blk, fifo, sock */
#define FT_NOACCESS   7               /* Not able to access */
#define FT_NOFOLLOW   8               /* Could not follow link */
#define FT_NOSTAT     9               /* Could not stat file */
#define FT_NOCHG     10               /* Incremental option, file not changed */
#define FT_DIRNOCHG  11               /* Incremental option, directory not changed */
#define FT_ISARCH    12               /* Trying to save archive file */
#define FT_NORECURSE 13               /* No recursion into directory */
#define FT_NOFSCHG   14               /* Different file system, prohibited */
#define FT_NOOPEN    15               /* Could not open directory */
#define FT_RAW       16               /* Raw block device */
#define FT_FIFO      17               /* Raw fifo device */
#define FT_DIRBEGIN  18               /* Directory at beginning (not saved) */
#define FT_INVALIDFS 19               /* File system not allowed for */
#define FT_INVALIDDT 20               /* Drive type not allowed for */
#define FT_REPARSE   21               /* Win NTFS reparse point */
#define FT_PLUGIN    22               /* Plugin generated filename */
#define FT_DELETED   23               /* Deleted file entry */
#define FT_BASE      24               /* Duplicate base file entry */
#define FT_RESTORE_FIRST 25           /* Restore this "object" first */
#define FT_JUNCTION  26               /* Win32 Junction point */
#define FT_PLUGIN_CONFIG 27           /* Object for Plugin configuration */
#define FT_PLUGIN_CONFIG_FILLED 28    /* Object for Plugin configuration filled by Director */

typedef struct checksum {
  SHA_CTX s;
  MD5_CTX m;
} checksum_t;

uint64_t debufsz = DEBUFSZ;
char *debuff = NULL;

static inline int checksum_init(checksum_t *c);
static inline int checksum_compute(volume_t *vol, stream_t *stream, 
    checksum_t *c, char *result);
static inline int checksum_update(checksum_t *c, char *data, int dlen);
static inline int get_attributes(volume_t *vol, stream_t *stream);
static inline size_t get_file(volume_t *vol, stream_t *stream, checksum_t *c);
static inline void hexdigest(char *digestin, char *hexout);


static inline int get_attributes(
    volume_t *vol,
    stream_t *stream)
{
  int rc; 
  while (1) {
    rc = stream_read(vol, stream);
    if (rc == 0) {
      printf("**End of volume**\n");
      return rc;
    }

    if (rc < 0) {
      warnx("Cannot process a stream record!");
      return 0;
    }

    if (stream->type != STREAM_UNIX_ATTRIBUTES)
      continue;

    return stream->stream.unixattr.type;
  }
}


static inline checksum_init(
    checksum_t *c)
{
  if (!SHA1_Init(&c->s)) {
    warnx("Internal error: Could not initialize SHA structure");
    return -1;
  }

  if (!MD5_Init(&c->m)) {
    warnx("Internal error: Could not initialize MD5 structure");
    return -1;
  }
}


static inline int checksum_update(
    checksum_t *c,
    char *data,
    int dlen)
{
  /* Update the shasum with what we know about the data */
  if (!SHA1_Update(&c->s, data, dlen)) {
    warnx("Internal error: Could not update SHA structure");
    return -1;
  }

  if (!MD5_Update(&c->m, data, dlen)) {
    warnx("Internal error: Could not update MD5 structure");
    return -1;
  }

  return 0;
}


static inline int checksum_compute(
    volume_t *vol,
    stream_t *stream,
    checksum_t *c,
    char *result)
{
  int chklen = 20;
  char cvolsum[128], cresult[128];
  char volsum[20];

  memset(cvolsum, 0, 128);
  memset(cresult, 0, 128);
  memset(result, 0, 20);
  
  if (stream->type == STREAM_SHA1_DIGEST) {
    if (stream->length != 20) {
      warnx("Cannot process at position %llu block number %d block offset: %d: Expected sha1 digest to be 20 bytes"
            " but it was %d (stream %d) bytes", vol->offset+vol->block.offset, vol->block.number, vol->block.offset, vol->record.length,
            stream->length);
        return -1;
    }

    /* Copy digest to our stack */
    memcpy(volsum, stream->data, 20);
    /* Finalize the shasum */
    if (!SHA1_Final(result, &c->s)) {
      warnx("Internal error: Could not finalize SHA structure");
      return -1;
    }
   chklen = 20;
  }
  else if (stream->type == STREAM_MD5_DIGEST) {
    if (stream->length != 16) {
      warnx("Cannot process at position %llu block number %d block offset: %d: Expected sha1 digest to be 20 bytes"
            " but it was %d (stream %d) bytes", vol->offset+vol->block.offset, vol->block.number, vol->block.offset, vol->record.length,
            stream->length);
      return -1;
   }

    /* Copy digest to our stack */
    memcpy(volsum, stream->data, 16);
    /* Finalize the md5sum */
    if (!MD5_Final(result, &c->m)) {
      warnx("Internal error: Could not finalize MD5 structure");
      return -1;
    }
    chklen = 16;
  }
  else {
    warnx("Asked to compute digest on a invalid stream type");
    return -1;
  }

  if (memcmp(result, volsum, chklen) != 0) {
    hexdigest(result, cresult);
    hexdigest(cvolsum, volsum);
    warnx("Cannot process position %d block number %d: SHA Checksum mismatch!\n"
          "SHA we computed: %s, Volume Computed: %s",
          vol->offset+vol->block.offset, vol->block.number,
          cresult, cvolsum);
    return -1;
  }

  return chklen;
}


static inline size_t get_file(
    volume_t *vol,
    stream_t *stream,
    checksum_t *c)
{
  int rc;
  size_t bytes;
  if (!debuff) {
    debuff = malloc(DEBUFSZ);
    if (!debuff) {
      warn("Cannot obtain memory for decompression buffer");
      return -1;
    }
  }

  while (1) {
    rc = stream_read(vol, stream);
    if (rc < 0) {
      warnx("Volume finished before file could be processed!\n");
      return bytes;
    }

    if (rc == 0) {
      warnx("Cannot process stream record type %d at position %llu block number %d",
        stream->type, vol->offset+vol->block.offset, vol->block.number);
      return -1;
    }

    switch (stream->type) {

    /* Compressed data stream */
    case STREAM_GZIP_DATA:
      memset(debuff, 0, DEBUFSZ);
      if (uncompress(debuff, &debufsz, stream->data, stream->length) != Z_OK) {
        warnx("Unable to decompress data buffer");
        return -1;
      }

      if (checksum_update(c, debuff, debufsz) < 0) {
        return -1;
      }

      bytes += debufsz;
      debufsz = DEBUFSZ;
    break;

    /* Normal stream */
    case STREAM_FILE_DATA:
      if (checksum_update(c, stream->data, stream->length) < 0)
        return -1;
      bytes += stream->length;
    break;

    /* Any other type of stream means end of file. Returnn read bytes */
    default:
      return bytes;
    break;
    }
  }
  return bytes;
}


static inline void hexdigest(
    char *digestin, 
    char *hexout)
{
  int i;
  memset(hexout, 0, 128);
  for (i=0; i < 20; i++) {
    snprintf(hexout+(i*2), 3, "%02hhx", digestin[i]);
  }
}

/* Read a file from the volume stream(s) */
/* A uncompressed file is represented as a series of
 * stream types:
 * stream type 1  (metadata)
 * stream type 2  (data)
 * stream type 3 or 10 (md5sum or sha1sum)
 *
 * It is expected the stream output will be well-ordered (never 2 1 10 for example)
 *
 * This function reads the stream and puts together a file found
 * with the three stream records. Further validation should be performed.
 *  - A Sha sum check against size of data
 *  - The attributes are valid.
 *
 *  We dont do compressed files.
 *  We dont look for extended attributes.
 */
int file_read(
    volume_t *vol, filedata_t *file_data)
{
  int attr, rc = -1, chklen = 0;
  stream_t stream;
  char result[20];
  checksum_t csum;

  if (checksum_init(&csum) < 0)
    goto fail;

  if (!file_data) {
    warn("Filedata struct is not set");
    goto fail;
  }

  memset(&stream, 0, sizeof(stream_t));
  memset(file_data, 0, sizeof(filedata_t));

  /* First, we must search for our record 1 type */
  attr = get_attributes(vol, &stream);
  if (attr <= 0)
    goto fail;
  memcpy(file_data->attr, stream.stream.unixattr.attr, 128);


  /* Actions next are determined by file type */
  switch(attr) {

  case FT_REG:
    if(get_file(vol, &stream, &csum) < 0)
      goto fail;
    if ((chklen = checksum_compute(vol, &stream, &csum, result)) <= 0)
      goto fail;
  break;

  case FT_REGE:
  default:
  break;

  }

fin:
  /* Time to fill in our filedata structure */
  file_data->volsessid = vol->block.vol_sessionid;
  file_data->voltime = vol->block.vol_sessiontime;
  file_data->fileindex = vol->record.fileindex;
  bin_to_base64(file_data->checksum, 64, result, chklen, 1);
  rc = 1;

fail:
  if (stream.data)
    free(stream.data);
  return rc;

}
