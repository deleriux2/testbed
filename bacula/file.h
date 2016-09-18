#ifndef _FILE_H_
#define _FILE_H_
#include "stream.h"

typedef struct filedata {
  int32_t volsessid;
  int32_t voltime;
  int32_t fileindex;
  char attr[128];
  char checksum[64];
} filedata_t;

int file_read(volume_t *vol, filedata_t *fdata);
#endif
