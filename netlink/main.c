#include "common.h"
#include "events.h"
#include "timer.h"
#include "netlink_if.h"
#include "config.h"
#include "nflog.h"

extern struct config *configuration;

/* test */
int main(
  const int argc,
  char **argv) {

  if (argc < 2) {
    fprintf(stderr, "Must print the path to the config file as the first argument\n");
    exit(1);
  }

  netlink_init();
  event_init();

  int rc = 0;
  int fd = netlink_open();
  if (fd < 0) {
    perror("Opening netlink socket");
    exit(1);
  }

  /* Must bring up interface resolution first */
  if (netlink_request_interfaces(fd) < 0) {
    perror("Sending request for network devices");
    exit(1);
  }

  while ((rc = netlink_recv(&fd)) > 0);
  if (rc < 0) {
    perror("Filling the initial cache");
    exit(1);
  }

  if (config_parse(argv[1]) < 0) {
    fprintf(stderr, "Error parsing config file. Aborting\n");
    exit(1);
  }

  if (event_add(fd, EPOLLIN, netlink_recv, &fd, sizeof(fd)) < 0) {
    perror("Adding event to event manager");
    exit(1);
  }

  if (nflog_start() < 0) {
    perror("Starting netfilter logging");
    exit(1);
  }

  if (event_loop() < 0) {
    perror("Event loop exited abnormally");
    exit(1);
  }
  exit(0);
  
}
