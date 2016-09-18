#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include "nfc_stats.h"

int main() {
  nfc_stats_t *stats =  nfc_stats_open("stats.dat", NFC_STATS_RDONLY);
  if (!stats) {
    perror("stats open");
    exit(1);
  }

  //nfc_stats_close(stats);

  //stats = nfc_stats_open("/tmp/nfc_stats.dat", NFC_STATS_RDONLY);
  //if (!stats) {
  //  perror("stats open2");
  //  exit(1);
  //}

//  if (nfc_stats_reset(stats) < 0) {
//    perror("stats reset");
//    exit(1);
//  }

//  if (!nfc_stats_add_group(stats, 1000, "CN", NF_STOP))
//    perror("add group 1");

//  if (!nfc_stats_add_group(stats, 1000, "RU", NF_STOP))
//    perror("add group 2");

//  nfc_stats_inc_count(stats, 1000, "RU");
//  nfc_stats_inc_count(stats, 1000, "RU");
//  nfc_stats_inc_count(stats, 1000, "RU");
//  nfc_stats_inc_count(stats, 1000, "RU");
//  nfc_stats_inc_count(stats, 1000, "RU");
//  if (!nfc_stats_add_group(stats, 1010, "GB", NF_STOP))
//    perror("add group 3");

//  if (!nfc_stats_add_group(stats, 1001, "GB", NF_STOP))
//    perror("add group 3");


  uint16_t grp;
  const char *p;

  for (grp = nfc_stats_get_all_groups(stats);
       grp != USHRT_MAX;
       grp = nfc_stats_get_next_group(stats))
  {
    for (p = nfc_stats_get_countries_per_group(stats, grp);
         p != NULL;
         p = nfc_stats_get_next_country(stats))
    {
      printf("%d: %s = %llu -> %s\n", grp, p, nfc_stats_get_count(stats, grp, p), nfc_stats_get_verdict(stats, grp, p) == NF_STOP ? "DROP" : "ACCEPT");
    }
  }

  nfc_stats_close(stats);

  exit(0);
}
