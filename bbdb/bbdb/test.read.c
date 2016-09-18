#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include "bbdb.h"

int main (
   int argc,
   const char **argv)
{
  enum verdict v;
  int i, k, j, m, k2;
  bbdb_t *bbdb = NULL;
  char ipfrom[32];
  char ipto[32];
  uint32_t high;
  uint32_t low;

  bbdb = bbdb_open("/var/mnt/backup/test.bbd");
  printf("Pristine: %d\n", bbdb->crypto->pristine);

  if (!bbdb)
    err(EXIT_FAILURE, "error");

/*
  #define TOTALKEYS 200000
  srand(1);
  for (i=0; i < TOTALKEYS; i++) {
    k = rand();
    if (i+32 < 32)
      continue;
    for (j=0; j < 32; j++) {
      m = htonl(k+j);
      inet_ntop(AF_INET, &m, ipfrom, 32);
//      printf("IP: %s\n", ipfrom);
      v = bbdb_verdict(bbdb, ipfrom);
      if (v != DROP) {
        printf("Stop: i = %u, j %u %s %u\n", i, j, ipfrom, ntohl(m));
        pause();
      }
    }
  }
*/

  btree_traverse_t trav;
  btree_traverse_init(bbdb->deny, &trav);

  while (btree_traverse_next(&trav, &low, &high)) 
    printf("Low: %u, High: %u\n", low, high);
  

  bbdb_close(bbdb);
}
