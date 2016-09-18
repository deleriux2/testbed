#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include "bbdb.h"

void print_checksum(
  char *checksum)
{
  int i;
  for (i=0; i < SHA256_DIGEST_LENGTH; i++) {
    printf("%hhx", checksum[i]);
  }
}

int main (
   int argc,
   const char **argv)
{
  enum verdict v;
  int i, k, k2, j, rc;
  bbdb_t *bbdb = NULL;
//  bbdb_t *bbdb2 = NULL;
  bbdb_diff_summary_t summary;
  bbdb_diff_record_t diff;
  bbdb_merge_summary_t summ;
  bbdb_merge_record_t merge;
  char ipfrom[32];
  char ipto[32];
  FILE *difffd;
  FILE *mergefd;

  bbdb = bbdb_new("/var/mnt/backup/test.bbd");
  if (!bbdb)
    err(EXIT_FAILURE, "error");

  #define TOTALKEYS 200000
  /* Put 2000000 random addresses into the service */
  srand(1);
  for (i=0; i < TOTALKEYS; i++) {
    k = rand();
    k2 = k + 32;
    k = htonl(k);
    k2 = htonl(k2);
    inet_ntop(AF_INET, &k, ipfrom, 32); 
    inet_ntop(AF_INET, &k2, ipto, 32); 
//    printf("i: %d, from: %s to: %s\n", i, ipfrom, ipto);
    bbdb_insert(bbdb, ipfrom, ipto, DROP);

  }


//  bbdb2 = bbdb_open("/var/mnt/backup/test2.bbd");

//  bbdb_import(bbdb, bbdb2);
//  bbdb_close(bbdb2);

  bbdb_vacuum(bbdb);
  bbdb_seal(bbdb, "key.pem", "root.der");

  /* Diff test */
  difffd = fopen("test.bbd.diff", "w");
  if (!difffd)
    err(EXIT_FAILURE, "Cannot open test.bbd.diff");

  bbdb_diff_init(bbdb, &summary);
  /* Write the diff file out */
  fwrite(&summary, sizeof(summary), 1, difffd);
 
  printf("Summary info:\n");
  printf("\tVersion: %llu\n\tRevelation: %llu\n\tPagecount: %u\n\n",
         summary.version, summary.revelation, summary.pagecount);

  while (bbdb_diff_next(&summary, &diff)) {
    /* Write out the diff records */
    fwrite(&diff, sizeof(diff), 1, difffd);
  }
  fclose(difffd);

  /* Begin merge test */
  for (i=0; i < 5000; i++) {
    k = rand();
    k2 = k + 32;
    k = htonl(k);
    k2 = htonl(k2);
    inet_ntop(AF_INET, &k, ipfrom, 32);
    inet_ntop(AF_INET, &k2, ipto, 32);
    bbdb_insert(bbdb, ipfrom, ipto, DROP);
  }

  bbdb_insert(bbdb, "0.0.0.0", "64.0.0.0", DROP);

  bbdb_vacuum(bbdb);
  bbdb_seal(bbdb, "key.pem", "root.der");


  difffd = fopen("test.bbd.diff", "r");
  mergefd = fopen("test.bbd.merge", "w");

  /* Read the summary first */
  fread(&summary, sizeof(summary), 1, difffd);

  /* Use diff summary to work out size of their pagemap */
  bbdb_merge_init(bbdb, &summ, &summary);
  fwrite(&summ, sizeof(summ), 1, mergefd);

  /* Fetch all new pages */
  while ((rc = bbdb_merge_new(&summ, &merge)) >= 0) {
    if (rc == 1)
      fwrite(&merge, sizeof(merge), 1, mergefd);
  }

  /* Fetch all changed and deleted pages */
  while (!feof(difffd)) {
    /* Read the diff record */
    fread(&diff, sizeof(diff), 1, difffd);
    rc = bbdb_merge_next(&summ, &diff, &merge);
    if (rc < 0) {
      assert(1==0);
      break;
    }
    else if (rc == 1) {
      fwrite(&merge, sizeof(merge), 1, mergefd);
    }
  }

  /* Rewrite the merge summary again */
  fseek(mergefd, 0, SEEK_SET);
  fwrite(&summ, sizeof(summ), 1, mergefd);

  fclose(mergefd);
  fclose(difffd);

  printf("Merge summary info:\n");
  printf("\tVersion: %llu\n\tRevelation: %llu\n\tSize: %u\n"
         "\tDeny Nodes: %llu\n\tAllow Nodes: %llu\n"
         "\tDeny Records: %llu\n\tAllow Records: %llu\n"
         "\tNumber of New Records: %llu\n"
         "\tNumber of Changed Records: %llu\n"
         "\tNumber of Deleted Records: %llu\n"
         "\tTotal Records: %llu\n"
         "\tDeny Tree Offset: %llu\n"
         "\tAllow Tree Offset: %llu\n",
         summ.version, summ.revelation, summ.pagecount,
         summ.deny_nodes, summ.allow_nodes,
         summ.deny_recs, summ.allow_recs,
         summ.added, summ.changed, summ.freed,
         summ.numrecs,
         summ.deny_offset, summ.allow_offset);
  bbdb_close(bbdb);

  /* Rebuild the originally assigned database */
  bbdb = bbdb_new("/var/mnt/backup/test.bbd");
  if (!bbdb)
    err(EXIT_FAILURE, "error");

  #define TOTALKEYS 200000
  /* Put 2000000 random addresses into the service */
  srand(1);
  for (i=0; i < TOTALKEYS; i++) {
    k = rand();
    k2 = k + 32;
    k = htonl(k);
    k2 = htonl(k2);
    inet_ntop(AF_INET, &k, ipfrom, 32); 
    inet_ntop(AF_INET, &k2, ipto, 32); 
    bbdb_insert(bbdb, ipfrom, ipto, DROP);
  }

  //bbdb2 = bbdb_open("/var/mnt/backup/test2.bbd");
  //bbdb_import(bbdb, bbdb2);
  bbdb_vacuum(bbdb);
  bbdb_seal(bbdb, "key.pem", "root.der");
  bbdb_close(bbdb);

  /* REMOVE Me used for getting good copy db */
  printf("FINISHING UP WITH ORIGINAL FILE\n");
  exit(0);

  bbdb = bbdb_open("/var/mnt/backup/test.bbd");

  /* Merge Apply Test */
  mergefd = fopen("test.bbd.merge", "r");
  if (!mergefd)
    err(EXIT_FAILURE, "Cannot open merge file");

  /* Read the summary */
  fread(&summ, sizeof(summ), 1, mergefd);

  /* Adjusts our mapping */
  if (!bbdb_apply_merge_init(bbdb, &summ))
    errx(EXIT_FAILURE, "Cannot apply merge");

  /* Perform the record merge */
  while (1) {
    fread(&merge, sizeof(merge), 1, mergefd);
    rc = bbdb_apply_merge_next(&summ, &merge);
    if (rc < 0) {
      printf("Something terrible happened\n");
      exit(1);
    }
    else if (rc == 0) {
      printf("I apparently did finish\n");
      break;
    }
  }
  fclose(mergefd);
  printf("Pristine: %d\n", bbdb->crypto->pristine);

  srand(1);
  for (i=0; i < TOTALKEYS; i++) {
    k = rand();
    k = htonl(k);
    for (j=0; j < 32; j++) {
      k = htonl(k)+j;
      inet_ntop(AF_INET, &k, ipfrom, 32); 
      bbdb_verdict(bbdb, ipfrom);
    }
  }
}
