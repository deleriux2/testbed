#include "volume.h"
#include "label.h"
#include "file.h"

#include <libgen.h>
#include <err.h>
#include <sysexits.h>
#include <string.h>

int main(const int argc, char **argv) {
  int totalfiles=0;
  int totalerrs=0;
  int totalgood=0;
  label_t label;
  filedata_t data;
  char logname[128];

  FILE *log = NULL;

  memset(logname, 0, 128);

  if (argc < 2) {
    fprintf(stderr, "Must provide a valid volume path\n");
    exit(1);
  }

  volume_t *vol = volume_open(argv[1]);

  if (!vol)
    exit(1);

  snprintf(logname, 128, "log-%s.log", basename(argv[1]));
  log = fopen(logname, "w");
  fprintf(log, "#fileindex,volsessionid,volsessiontime,lstat,md5\n");

  printf("Scanning.....\n");
  int i, rc;
  /* We begin by making a read of the volume label */
  rc = label_vol_read(vol, &label);

  record_get(vol);
  rc = label_sos_read(vol, &label);
  printf("jobid: %u\n",
    label.labels.sos_label.jobid);
  if (rc <= 0)
    errx(EX_SOFTWARE, "LABEL");

  for (i=0; i > -1; i++) {
    rc = file_read(vol, &data);
    totalfiles++;
    if (rc < 0) {
      break;
    }
    if (rc == 0) {
      totalerrs++;
      continue;
    }

    fprintf(log, "\"%d\",\"%d\",\"%d\",\"%s\",\"%s\"\n", data.fileindex, data.volsessid, data.voltime, data.attr, data.checksum);
    printf("\"%d\",\"%d\",\"%d\",\"%s\",\"%s\"\n", data.fileindex, data.volsessid, data.voltime, data.attr, data.checksum);
    fflush(log);
    totalgood++;
  }
 
  printf("Scanned %d files. %d failed validation, %d succeeded\n", totalfiles, totalerrs, totalgood);
  exit(0);
}
