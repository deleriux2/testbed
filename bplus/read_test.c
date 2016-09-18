#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "page.h"
#include "index.h"
#include "crypto.h"
#include "license.h"
#include "btree.h"

#define TOTALKEYS 20000000

int main ()
{
  errno = 0;
  int fd = open("./moo.txt", O_RDWR|O_CREAT, 0660);
  int i;
  int rc;
  int sz;
  struct timeval now, then;
  pagemap_t *map;
  page_t *page;
  index_t *index;
  crypto_t *crypto;
  license_t *license;
  btree_t *tree;
  char buffer[256];
  memset(buffer, 0, 256);
  ipnet_t *ips = NULL;
  enum verdict v;


  map = pagemap_open(fd);
  index = index_open(map);
  tree = btree_open(map, index);
  crypto = crypto_open(map, index);
  license = license_open(map, index);


  srand(1);
  gettimeofday(&then, NULL);
  for (i=0; i < TOTALKEYS; i++) {
    //k = rand();
    v = btree_verdict(tree, i);
    if (v != DROP)
      printf("%u: %u %d\n", i, i, v);
  }
  gettimeofday(&now, NULL);
  printf("Then: %d.%06d\nNow:  %d.%06d\n",
    then.tv_sec, then.tv_usec,
    now.tv_sec, now.tv_usec
    );

  crypto_close(crypto);
  license_close(license);
  btree_close(tree);
  index_close(index);
  pagemap_close(map);
}
