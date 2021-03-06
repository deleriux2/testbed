#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <netinet/in.h>

struct config {
  char name[256];
  int group;
  struct sockaddr_in mcast_addr;
  struct sockaddr_in local_addr;
  char interface[128];
  int iface_idx;
  int payloadsz;
  int mcastfd;
  
  struct config *next;
};


struct config * config_new(void);
void config_destroy(void);
int config_parse(char *name);

#endif
