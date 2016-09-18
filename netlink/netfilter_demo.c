#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libnetfilter_log/libnetfilter_log.h>

#define SELECTED_ADDR "127.0.0.1"
#define SELECTED_PORT "15000"
#define MULTICAST_ADDR "224.0.0.200"
#define MULTICAST_PORT "14575"

int mcastfd = -1;
struct addrinfo *multicast = NULL;

void setup_mcast()
{
  int rc;
  struct addrinfo *ai, hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST;

  memset(&multicast, 0, sizeof(multicast));

  rc = getaddrinfo(SELECTED_ADDR, SELECTED_PORT, &hints, &ai);
  if (rc) {
    fprintf(stderr, "Cannot get address: %s\n", gai_strerror(rc));
    goto fail;
  }

  rc = getaddrinfo(MULTICAST_ADDR, MULTICAST_PORT, &hints, &multicast);
  if (rc) {
    fprintf(stderr, "Cannot setup multicast struct: %s\n", gai_strerror(rc));
  }

  mcastfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (mcastfd < 0) {
    perror("Cannot setup multicast socket");
    goto fail;
  }

  if (bind(mcastfd, ai->ai_addr, ai->ai_addrlen) < 0) {
    perror("Cannot bind to address");
    goto fail;
  }

  if (connect(mcastfd, multicast->ai_addr, multicast->ai_addrlen) < 0) {
    perror("Cannot connect to multicast address");
    goto fail;
  }

  return;

fail:
  if (mcastfd >= 0)
    close(mcastfd);
  if (ai)
    freeaddrinfo(ai);

  if (multicast)
    freeaddrinfo(multicast);
  exit(1);
}

int callback(
  struct nflog_g_handle *g,
  struct nfgenmsg *nfmsg,
  struct nflog_data *nfld,
  void *data)
{
  printf("here!\n");
  if (send(mcastfd, "here!\n", sizeof("here!\n"), 0) < 0) {
    perror("Cannot send out packet");
    exit(1);
  }
  return 0;
}

int main() {
  setup_mcast();
  struct nflog_handle *h = NULL;
  struct nflog_g_handle *g = NULL;
  int rc, fd;
  char buf[1200];

  printf("opening nflog\n");
  h = nflog_open();
  if (h < 0) {
    perror("cannot open netfilter log");
    exit(1);
  }

  printf("binding nf log to AF_INET\n");
  if (nflog_bind_pf(h, AF_INET) < 0) {
    perror("cannot bind nf log to AF_INET");
    goto fail;
  }

  printf("binding this socket to group 0\n");
  g = nflog_bind_group(h, 0);
  if (!g) {
    perror("cannot bind nf log to group 0");
    goto fail;
  }

  printf("setting mode of packet handling to COPY PACKET\n");
  if (nflog_set_mode(g, NFULNL_COPY_PACKET, 1200) < 0) {
    perror("cannot set mode on group handler");
    goto fail;
  }

  printf("setting callback for group 0\n");
  nflog_callback_register(g, &callback, NULL);

  fd = nflog_fd(h);

  while ((rc = recv(fd, buf, 1200, 0)) && rc >= 0) {
    /* This will invoke the callback for the group */
    printf("Got a packet to handle: %d bytes\n", rc);
    if (send(mcastfd, buf, rc, 0) <  0) {
      perror("Failed to send packet");
      goto fail;
    }
//    nflog_handle_packet(h, buf, rc);
  }

  if  (rc < 0) {
    perror("Cannot sendfile");
    goto fail;
  }

  

fail:
  if (g)
    nflog_unbind_group(g);
  if (h)
    nflog_close(h);
  exit(1);
}

