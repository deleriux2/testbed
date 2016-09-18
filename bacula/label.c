#include "label.h"
#include <string.h>
#include <byteswap.h>
#include <err.h>
#include <limits.h>

#define VOL_LABEL_MAGIC "Bacula 1.0 immortal\n"
#define VOL_VERSION 11
#define VOL_LABEL_POOLTYPE "Backup"
#define NAMESZ     128

static inline int get_common_label(volume_t *vol, label_t *label);
static inline int validate_label(volume_t *vol, label_t *label);
static inline int get_session_label(char *p, label_t *label);

static inline int read_int32(void *ptr, int32_t *val)
{
  int32_t *i = ptr;
  *val = bswap_32(*i);
  return 4;
}

static inline int read_uint32(void *ptr, uint32_t *val)
{
  uint32_t *i = ptr;
  *val = bswap_32(*i);
  return 4;
}

static inline int read_int64(void *ptr, int64_t *val)
{
  int64_t *i = ptr;
  *val = bswap_64(*i);
  return 8;
}

static inline int read_uint64(void *ptr, uint64_t *val)
{
  uint64_t *i = ptr;
  *val = bswap_64(*i);
  return 8;
}

static inline int read_string(void *ptr, char *str, int max)
{  
  int i;
  char *src = (char*)(ptr);
  char *dest = str;
  for (i=0; i<max && src[i] != 0;  i++) {
    dest[i] = src[i];
  }
  dest[i++] = 0;            /* terminate output string */
  ptr += i;                /* update pointer */
  return i;
}


static inline int get_common_label(
    volume_t *vol,
    label_t *label)
{
  int len=0;
  int total=0;
  record_t *rec = &vol->record;
  char *p = vol->block.data+vol->block.offset;

  len = read_string(p, label->id, 128); p += len; total += len;
  len = read_int32(p, &label->version); p += len; total += len;

  return total;
}


static inline int get_session_label(
    char *p,
    label_t *label)
{
  int len=0;
  int total = 0;

  len = read_int32(p, &label->labels.sos_label.jobid);
  p += len;
  total += len;
  len = read_int64(p, &label->labels.sos_label.writetime); 
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.poolname, NAMESZ);
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.pooltype, NAMESZ);
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.jobname, NAMESZ);
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.clientname, NAMESZ);
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.jobidname, NAMESZ);
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.filesetname, NAMESZ);
  p += len;
  total += len;
  len = read_uint32(p, &label->labels.sos_label.jobtype); 
  p += len;
  total += len;
  len = read_uint32(p, &label->labels.sos_label.joblevel); 
  p += len;
  total += len;
  len = read_string(p, label->labels.sos_label.filesetsum, NAMESZ);
  p += len;
  total += len;

  return total;
}


static inline int validate_label(
    volume_t *vol,
    label_t *label)
{
  uint64_t now;
  block_t *block = &vol->block;

  /* Expect to be at zeroeth block */
  if (block->number != 0) {
    warnx("At block %d but expected block 0");
    goto fail;
  }

  if (label->labels.vol_label.labeltime > label->labels.vol_label.writetime) {
    warnx("Volume labelled at %llu yet written at %llu."
         " Label time should never be greater than write time");
    goto fail;
  }

  now = (uint64_t)time(NULL)*1000000llu;
  if (now < label->labels.vol_label.writetime) {
    warnx("Volume is listed as being written in the future at %llu", 
          label->labels.vol_label.writetime);
    goto fail;
  }

  if (strncmp(label->id, VOL_LABEL_MAGIC, 
             strlen(VOL_LABEL_MAGIC)) != 0) {
    warnx("Label presented unexpected volume ID %s", label->id);
    goto fail;
  }

  if (label->version < VOL_VERSION) {
    warnx("This program supports only version %d volumes", VOL_VERSION);
    goto fail;
  }

  if (strncmp(label->labels.vol_label.volname, 
                  vol->name, NAME_MAX) != 0) {
    warnx("The volume name is %s yet the filename is %s",
          label->labels.vol_label.volname, vol->name);
    goto fail;
  }

  if (strncmp(label->labels.vol_label.pooltype, 
      VOL_LABEL_POOLTYPE, strlen(VOL_LABEL_POOLTYPE)) != 0) {
    warnx("Pooltype is labelled as %s but should be %s",
      label->labels.vol_label.pooltype, VOL_LABEL_POOLTYPE);
  }

  return 1;

fail:
  return 0;
}



/* Reads a session label */
/* Expects the record to actually be present! */
int label_sos_read(
    volume_t *vol,
    label_t *label)
{
  block_t *block;
  record_t *rec;
  int rc;
  char *p;

  if (!vol||!label) {
    warnx("Volume is not properly set");
    goto fail;
  }

  memset(label, 0, sizeof(label_t));
  block = &vol->block;
  rec = &vol->record;

  p = block->data + block->offset;

  if (rec->fileindex != SOS_LABEL) {
    warnx("Expected a start of session label, but got index type %d\n", rec->fileindex);
    goto fail;
  }

  if (rec->length < 50 || rec->length > 2000000) {
    warnx("Invalid record length %d");
    goto fail;
  }

  label->type = SOS_LABEL;

  /* Get common values */
  rc = get_common_label(vol, label);
  if (!rc)  
    goto fail;

  p += rc;

  /* Get the start of session label */
  rc = get_session_label(p, label);
  if (rc <= 0)
    goto fail;
  p += rc;

// removeme
  goto fail;

  block->offset += vol->record.length;
  return 1;

fail:
  block->offset += vol->record.length;
  return -1;
}


/* Reads a volume label */
int label_vol_read(
    volume_t *vol,
    label_t *label)
{
  int rc;
  char *p;
  record_t *rec = NULL;
  block_t *block = NULL;

  if (!vol||!label) {
    warnx("Volume is not properly set");
    goto fail;
  }

  memset(label, 0, sizeof(label_t));

  rec = &vol->record;
  block = &vol->block;

  if (vol->offset == 0) {
    if (record_get(vol) <= 0) {
      warnx("Unable to retrieve valid record");
      goto fail;
    }
  }

  p = block->data + block->offset;

  if (rec->fileindex != VOL_LABEL) {
    warnx("Expected a volume label, but got index type %d\n", rec->fileindex);
    goto fail;
  }

  if (rec->length < 50 || rec->length > 2000000) {
    warnx("Invalid record length %d");
    goto fail;
  }

  label->type = VOL_LABEL;

  /* Get common values */
  rc = get_common_label(vol, label);
  if (!rc) 
    goto fail;

  p += rc;
  /* Time in millionths of a second since epoch */
  p += read_int64(p, &label->labels.vol_label.labeltime);
  p += read_int64(p, &label->labels.vol_label.writetime);
  /* Next two values are unused in version 11 */
  p += 16;
  p += read_string(p, label->labels.vol_label.volname, 128);
  p += read_string(p, label->labels.vol_label.prev_volname, 128);
  p += read_string(p, label->labels.vol_label.poolname, 128);
  p += read_string(p, label->labels.vol_label.pooltype, 128);
  p += read_string(p, label->labels.vol_label.medianame, 128);
  p += read_string(p, label->labels.vol_label.hostname, 128);
  p += read_string(p, label->labels.vol_label.labelprog, 128);
  p += read_string(p, label->labels.vol_label.progver, 128);
  p += read_string(p, label->labels.vol_label.progbuild, 128);

  if (!validate_label(vol, label))
    goto fail;

  block->offset += vol->record.length;
  return 1;
fail:
  block->offset += vol->record.length;
  return -1;
}
