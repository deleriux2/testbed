#ifndef _STREAM_H
#define _STREAM_H
#include "volume.h"
#include <limits.h>
#include <sys/stat.h>

#define ATTR_MAX 128

#define STREAM_TYPE_NONE          0
#define STREAM_UNIX_ATTRIBUTES    1
#define STREAM_FILE_DATA          2
#define STREAM_MD5_DIGEST         3
#define STREAM_GZIP_DATA          4
#define STREAM_SHA1_DIGEST        10

#define PRE_LABEL   -1                /* Vol label on unwritten tape */
#define VOL_LABEL   -2                /* Volume label first file */
#define EOM_LABEL   -3                /* Writen at end of tape */
#define SOS_LABEL   -4                /* Start of Session */
#define EOS_LABEL   -5                /* End of Session */
#define EOT_LABEL   -6                /* End of physical tape (2 eofs) */
#define SOB_LABEL   -7                /* Start of object -- file/directory */
#define EOB_LABEL   -8                /* End of object (after all streams) */

typedef struct stream {
  int type;
  union {
    struct {
      int32_t fileindex;
      int32_t type;
      char name[NAME_MAX];
      char attr[ATTR_MAX];
      struct stat stat;
    } unixattr;

    struct {
      FILE *f;
    } filedata;
  } stream;
  void *data;
  int length;
} stream_t;



void stream_init(void);

int stream_read(volume_t *vol, stream_t *rtype);

#endif
