#ifndef _LABEL_H
#define _LABEL_H
#include "volume.h"

#define PRE_LABEL   -1                /* Vol label on unwritten tape */
#define VOL_LABEL   -2                /* Volume label first file */
#define EOM_LABEL   -3                /* Writen at end of tape */
#define SOS_LABEL   -4                /* Start of Session */
#define EOS_LABEL   -5                /* End of Session */
#define EOT_LABEL   -6                /* End of physical tape (2 eofs) */
#define SOB_LABEL   -7                /* Start of object -- file/directory */
#define EOB_LABEL   -8                /* End of object (after all streams) */

#define NAMESZ     128
#define SESSION_LABEL \
      int32_t jobid; \
      time_t writetime; \
      char poolname[NAMESZ]; \
      char pooltype[NAMESZ]; \
      char jobname[NAMESZ]; \
      char clientname[NAMESZ]; \
      char jobidname[NAMESZ]; \
      char filesetname[NAMESZ]; \
      uint32_t jobtype; \
      uint32_t joblevel; \
      char filesetsum[NAMESZ]

typedef struct label {
  int type;
  char id[32];
  int32_t version;
  union {
    struct {
      int64_t labeltime;
      int64_t writetime;
      char volname[NAMESZ];
      char prev_volname[NAMESZ];
      char poolname[NAMESZ];
      char pooltype[NAMESZ];
      char medianame[NAMESZ];
      char hostname[NAMESZ];
      char labelprog[50];
      char progver[50];
      char progbuild[50];      
    } vol_label;

    struct {
      SESSION_LABEL;
    } sos_label;

    struct {
      SESSION_LABEL;
      uint32_t jobfiles;
      uint64_t jobbytes;
      uint32_t startblock;
      uint32_t endblock;
      uint32_t startfile;
      uint32_t endfile;
      uint32_t errors;
      uint32_t status;
    } eos_label;
  } labels;
} label_t;

int label_vol_read(volume_t *vol, label_t *label);
int label_sos_read(volume_t *vol, label_t *label);

#undef NAMESZ
#undef SESSION_LABEL
#endif
