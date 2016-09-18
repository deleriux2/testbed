#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <pthread.h>

#include <sys/time.h>
#include <arpa/inet.h>

#include "bbdb.h"

#define KEYS 16000000
#define NUMTHREADS 1
#define TOTALKEYS KEYS / NUMTHREADS
#define BBDBFILE "/var/mnt/backup/test.bbd"
bbdb_t *bbdb = NULL;
pthread_barrier_t barr;

void bye(
    int num)
{
  bbdb_disconnect(bbdb);
  pthread_exit(0);
}

void * do_work(
    void *data)
{
  int i,j;
  int key;
  int rand = 1;
  enum verdict v;
  char ips[32];
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = bye;
  if (sigaction(SIGTERM, &sa, NULL) < 0)
    err(EXIT_FAILURE, "sigaction");


  /* Wait at the barrier */
  bbdb_connect(bbdb);
  pthread_barrier_wait(&barr);

//  for (i=0; i < TOTALKEYS; i++) {
  for(;;) {
    memset(ips, 0, sizeof(ips));
    rand = rand_r(&rand);
    key = ntohl(rand);
    inet_ntop(AF_INET, &rand, ips, 32);
    for (j=0; j < 1; j++)
      v = bbdb_verdict(bbdb, ips);
  }
  bbdb_disconnect(bbdb);
  return NULL;
}


static double timediff(
    struct timeval *now,
    struct timeval *then)
{
  double high;
  double low;

  high  = (double)(now->tv_sec);
  high += ((double)(now->tv_usec) / 1000000);
  low   = (double)(then->tv_sec);
  low  += ((double)(then->tv_usec) / 1000000);

  return high - low;
}


int main() {
  int i;
  bbdb = bbdb_open(BBDBFILE);
  pthread_t threads[NUMTHREADS];
  bbdb_merge_summary_t summary;
  bbdb_merge_record_t merge;
  struct timeval then;
  struct timeval now;
  float time_difference;
  FILE *fd;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;

  if (!bbdb)
    err(EXIT_FAILURE, "Cannot open bbdb file");

  pthread_barrier_init(&barr, NULL, NUMTHREADS+1);

  for (i=0; i < NUMTHREADS; i++) {
    pthread_create(&threads[i], NULL, do_work, NULL);
  }

  if (sigaction(SIGTERM, &sa, NULL) < 0)
    err(EXIT_FAILURE, "sigaction");

  pthread_barrier_wait(&barr);
  gettimeofday(&then, NULL);

  /* Open the merge file */
  fd = fopen("test.bbd.merge", "r");
  if (!fd)
    err(EXIT_FAILURE, "Cannot open merge file");

  /* Read the merge summary */
  fread(&summary, sizeof(summary), 1, fd);

  /* Prepare our mapping */
  printf("Preparing to merge..\n");
  if (!bbdb_apply_merge_init(bbdb, &summary))
    err(EXIT_FAILURE, "UNable to apply merge initialization");
  printf("Preparations complete\n");

  while (!feof(fd)) {
    /* Read the next merge record */
    fread(&merge, sizeof(merge), 1, fd);
    /* Apply the merge record */
    if (bbdb_apply_merge_next(&summary, &merge))
      continue;
  }
  fclose(fd);

  printf("The merge was completed. Waiting 5 more seconds before termination.\n");
  sleep(5);
  

  for (i=0; i < NUMTHREADS; i++) {
    pthread_kill(threads[i], SIGTERM);
    pthread_join(threads[i], NULL);
  }

  gettimeofday(&now, NULL);

  printf("Finished records check in %.06f seconds\n", timediff(&now, &then));
  printf("Hits: %llu\n", bbdb->deny->hits + bbdb->allow->hits);
  printf("Misses: %llu\n", bbdb->deny->misses + bbdb->allow->misses);
  printf("LRU Hits: %llu\n", lru_hits());
  printf("LRU Misses: %llu\n", lru_misses());
  bbdb_close(bbdb);
  exit(0);
}
