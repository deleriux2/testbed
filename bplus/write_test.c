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
  printf("INDEX_RECORDS_MAX: %llu\n", INDEX_RECORDS_MAX);
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

  srand(1); int k;
  for (i=0; i < TOTALKEYS; i++) {
    if ((i % 1000000) == 0)
      printf("Inserts: %d\n", i);
    //k = rand();
    if (btree_insert(tree, i, DROP) == DUPLICATE)
      continue;
  }
  btree_close(tree);

  crypto = crypto_open(map, index);
  if (!crypto_certificate_set(crypto, "./root.der"))
    printf("Failed to load certificate\n");
  else
    printf("Success loading certificate\n");

  if (!crypto_certificate_set_private_key(crypto, "key.pem"))
    printf("Failed to load private key\n");
  else
    printf("Success loading private key\n");

  license = license_open(map, index);
  license_uid_set(license, 1);
  license_flow_set(license, LICENSE_MODE_IN|LICENSE_MODE_OUT);
  license_expiry_set(license, time(NULL)+(3600*3));
  license_identification_set(license, "E07EE82B-DAD7-DD11-BDA8-10BF488850EE");
  license_ip_add(license, "192.168.1.0", 24);
  license_ip_add(license, "192.168.2.0", 24);
  license_ip_add(license, "192.168.3.0", 24);

  license_close(license);
  crypto_seal(crypto);
  crypto_close(crypto);
  index_close(index);
  pagemap_close(map);
  printf("OK\n");
}
