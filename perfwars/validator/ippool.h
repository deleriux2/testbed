#ifndef _IPPOOL_H
#define _IPPOOL_H
#include "common.h"

typedef struct ippool {
  struct sockaddr_in6 *addrs;
  int total;
  int current;

  pthread_mutex_t lock;
} ippool_t;

ippool_t * ippool_init_src(char *desthost, char *destport);
ippool_t * ippool_init_dst(char *desthost, char *destport);
void ippool_destroy(ippool_t *ip);
struct sockaddr_in6 * ippool_next(ippool_t *ipp);

#endif
