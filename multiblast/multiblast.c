/* The objective of this test is to push a series of packets out over multicast
 * as quickly as possible and to then echo back the result */

/* System includes */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>

/* For sockets */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <netdb.h>
#include <ifaddrs.h>

/* For polling */
#include <sys/epoll.h>

#define MAX_PKT_SZ 1200
#define MAX_PKT_NUM 10000

#define MCAST_HOST_DEFAULT "224.0.0.251"
#define MCAST_PORT_DEFAULT "55555"
#define MCAST_IFACE_DEFAULT "eth0"
#define MCAST_NUMPACKETS_DEFAULT 100
#define MCAST_PACKETSIZE_DEFAULT 128
#define MAX_SOURCES 16

struct test_packet {
  struct timespec sendtime;
  struct timespec recvtime;
  uint32_t seqno;
};

struct test_result {
  struct timespec sendtime;
  struct timespec recvtime;
  uint32_t seqno;
  struct sockaddr_in sources[MAX_SOURCES];
  int naddrs;
  int in_pktsz;
  int rep_pktsz;
  bool malformed;
  bool out_of_sequence;
};

struct test_result *res;

/* Global config */
struct config {
  struct sockaddr_in dst;
  char *iface;
  char *mcast_addr;
  char *mcast_port;
  size_t packet_sz;
  int num_packets;
  bool listen_mode;
  int last_seq;
} config;


static void print_usage(
    void)
{
  printf(
    "Usage: multiblast [OPTION]\n"
    "Try multiblast --help for more information.\n"
  );
}

static void print_help(
    void)
{
  printf(
    "Usage: multiblast [OPTION] [listen]\n"
    "Perform a multicast based burst in order to test network robostness\n"
    "and reliability. This should be ran on at least two hosts to determine\n"
    "if it is reliable or not.\n"
    "\n"
    "Accepts one argument: \"listen\" which when set tells the program to\n"
    "wait for recieve packets to resent back to the original sender.\n"
    "\n"
    "Available options:\n"
    "  -a   --address      ADDRESS is the multicast group to use.\n"
    "  -h   --help         Prints this help.\n"
    "  -i   --interface    IFACE is the network interface to bind to.\n"
    "  -n   --num-packets  NUM is the number of packets to send and expect\n"
    "                      back.\n"
    "  -p   --port         PORT is the multicast port to use over UDP.\n"
    "  -s   --size         SIZE is the size of each packet, padded to send.\n"
    "  -u   --usage        Print a brief usage message\n"
    "\n"
  );
}


static void parse_config(
    char argc,
    char **argv)
{
  int rc;
  int c;
  int optidx=0;

  memset(&config, 0, sizeof(config));

  static struct option loptions[] = {
    {"interface", required_argument, 0, 'i'},
    {"address", required_argument, 0, 'a'},
    {"port", required_argument, 0, 'p'},
    {"packet-size", required_argument, 0, 's'},
    {"num-packets", required_argument, 0, 'n'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0 ,0}
  };

  while (1) {
    c = getopt_long(argc, argv, "a:i:hup:s:n:", loptions, &optidx);
    if (c < 0)
      break;

    switch(c) {

      case 'i':
      if (config.iface)
        goto duplicate;
      config.iface = strdup(optarg);
      if (!config.iface)
        goto syserr;
      break;

      case 'a':
      if (config.mcast_addr)
        goto duplicate;
      config.mcast_addr = strdup(optarg);
      if (!config.mcast_addr)
        goto syserr;
      break;

      case 'p':
      if (config.mcast_port)
        goto duplicate;
      config.mcast_port = strdup(optarg);
      if (!config.mcast_port)
        goto syserr;
      break;

      case 's':
      if (config.sz > 0)
        goto duplicate;
      config.sz = atoi(optarg);
      if (config.sz <= 0 || config.packet_sz >= MAX_PKT_SZ) {
        err(EXIT_FAILURE, "Packet size must be between %d and %d bytes",
            0, MAX_PKT_SZ);
      }
      break;

      case 'n':
      if (config.num_packets > 0)
        goto duplicate;
      config.num_packets = atoi(optarg);
      if (config.num_packets <= 0 || config.num_packets > MAX_PKT_NUM) {
        err(EXIT_FAILURE, "Packet number must be between 1 and %d packets",
                          MAX_PKT_NUM);
      }
      break;

      case 'u':
        print_usage();
        exit(0);
      break;

      case 'h':
        print_help();
        exit(0);
      break;

      default:
        print_usage();
        exit(1);
      break;
    }
  }

  /* Process defaults */
  if (!config.iface) {
    config.iface = strdup(MCAST_IFACE_DEFAULT);
    if (!config.iface)
      goto syserr;
  }
  if (!config.mcast_addr) {
    config.mcast_addr = strdup(MCAST_HOST_DEFAULT);
    if (!config.mcast_addr)
      goto syserr;
  }
  if (!config.mcast_port) {
    config.mcast_port = strdup(MCAST_PORT_DEFAULT);
    if (!config.mcast_port)
      goto syserr;
  }
  if (!config.num_packets)
    config.num_packets = MCAST_NUMPACKETS_DEFAULT;
  if (!config.packet_sz)
    config.packet_sz = MCAST_PACKETSIZE_DEFAULT;

  if (argc-optind == 1) {
    if (strncmp(argv[optind], "listen", 6) != 0) {
      fprintf(stderr, "Expect only one parameter: listen\n");
      print_usage();
      exit(1);
    }
    else {
      config.listen_mode = true;
    }
  }
  else if (argc-optind > 1) {
    fprintf(stderr, "Expect only one parameter: listen\n");
    print_usage();
    exit(1);
  }
  return;

duplicate:
  errx(EXIT_FAILURE, "Options %s has been passed more than once",
                    loptions[optidx].name);

syserr:
  err(EXIT_FAILURE, "System error processing option %s", 
                    loptions[optidx].name);
}


static int create_poll(
    int timer,
    int socket)
{
  struct epoll_event ev;
  int fd = -1;

  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;

  fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0)
    err(EXIT_FAILURE, "Cannot create polling object");

  /* Add the timer */
  ev.data.fd = timer;
  if (epoll_ctl(fd, EPOLL_CTL_ADD, timer, &ev) < 0)
    err(EXIT_FAILURE, "Cannot add timer to polling object");

  /* Add the socket */
  ev.data.fd = socket;
  if (epoll_ctl(fd, EPOLL_CTL_ADD, socket, &ev) < 0)
    err(EXIT_FAILURE, "Cannot add socket to polling object");

  return fd;
}

static int create_multicast_socket(
    char *iface,
    char *mc_addr,
    char *mc_port)
{
  int rc = -1;
  int fd = -1;
  struct sockaddr_in in, *tmp;
  struct ifaddrs *ips, *ip;
  int portno_l = 0;
  unsigned short portno = 0;
  /* The below is statically allocated, no need to free */
  struct protoent *proto = getprotobyname("udp");
  struct ip_mreqn mreq;

  /* Convert port number */
  portno_l = atoi(mc_port);
  if (portno_l <= 0 || portno_l > 65535)
    errx(EXIT_FAILURE, "Port number assignment must be beteween 1 and 65535");
  portno = htons((unsigned short)portno_l);

  memset(&in, 0, sizeof(in));
  memset(&mreq, 0, sizeof(mreq));
  memset(&config.dst, 0, sizeof(config.dst));

  /* Create the multicast structure for membership to multicast group */
  mreq.imr_multiaddr.s_addr = inet_addr(mc_addr);
  mreq.imr_ifindex = if_nametoindex(iface);
  if (mreq.imr_ifindex == 0)
    err(EXIT_FAILURE, "Cannot find interface");

  /* Create the binding address */
  if (getifaddrs(&ips) < 0)
    err(EXIT_FAILURE, "Cannot find IP address");
  for (ip=ips; ip != NULL; ip=ip->ifa_next) {
    if (strncmp(ip->ifa_name, iface, 16) == 0 && ip->ifa_addr->sa_family == AF_INET)
      break;
  }
  if (!ips)
    errx(EXIT_FAILURE, "There is no IP address assigned to this interface");
  in.sin_family = AF_INET;
  in.sin_port = portno;
  tmp = (struct sockaddr_in*)ip->ifa_addr;
  in.sin_addr.s_addr = INADDR_ANY;
  mreq.imr_address.s_addr = tmp->sin_addr.s_addr;
  freeifaddrs(ips);

  /* Create the socket */
  fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, proto->p_proto);
  if (fd < 0)
    err(EXIT_FAILURE, "Cannot create multicast socket");
  rc =1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc)) < 0)
    err(EXIT_FAILURE, "Cannot reuse socket");

  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0)
    err(EXIT_FAILURE, "Cannot bind to device %s", iface);

  /* Setup the binding interface for multicast */
  if (bind(fd, (struct sockaddr *)&in, sizeof(in)) < 0)
    err(EXIT_FAILURE, "Cannot bind to interface %s", iface);

  /* Register our interest in receiveing multicast packages from our group */
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    err(EXIT_FAILURE, "Cannot register for multicast group");

  /* Dont loopback our multicast messages */
  rc = 0;
  if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &rc, sizeof(rc)) < 0)
    err(EXIT_FAILURE, "Cannot register for multicast group");


  /* Fill in dst */
  config.dst.sin_family = AF_INET;
  config.dst.sin_port = portno;
  config.dst.sin_addr.s_addr = inet_addr(mc_addr);

  return fd;
}

static struct test_result * get_result(
    int hseqno)
{
  return &res[ntohl(hseqno)];
}

static void send_multicast(
    int fd)
{
  struct test_packet pkt;
  int i;
  int rc;
  char padding[MAX_PKT_SZ];

  for (i=0; i < config.num_packets; i++) {
    clock_gettime(CLOCK_REALTIME, &pkt.sendtime);
    memset(&pkt.sendtime, 0, sizeof(pkt.sendtime));
    pkt.seqno = htonl(i);
    memset(padding, 0, config.packet_sz);
    memcpy(padding, &pkt, sizeof(struct test_packet));

    /* Copy into test table */
    memcpy(&res[i], &pkt, sizeof(pkt));
    res[i].in_pktsz = config.packet_sz;
    res[i].naddrs = 0;

    rc = sendto(fd, padding, config.packet_sz, MSG_NOSIGNAL, &config.dst,
           sizeof(config.dst));
    if (rc != config.packet_sz)
      err(EXIT_FAILURE, "Failed to send packet on iteration %d: rc = %d", i, rc);
  }

  return; 
}

static void recv_multicast(
    int fd)
{
  struct sockaddr_in rcv;
  struct test_packet *pkt;
  int rc, slen=sizeof(rcv);
  char buf[MAX_PKT_SZ];
  memset(buf, 0, sizeof(buf));

  while (1) {
    rc = recvfrom(fd, buf, MAX_PKT_SZ, 0, (struct sockaddr *)&rcv, &slen);
    if (rc <= 0)
      err(EXIT_FAILURE, "Cannot retrieve packet. Aborting");

    /* Copy the packet contents into a packet, modify the contents then
     * sent back to the source host */

    pkt = (struct test_packet *)buf;
    clock_gettime(CLOCK_REALTIME, &pkt->recvtime);
    if (sendto(fd, buf, rc, MSG_NOSIGNAL, &rcv, slen) < 0)
      err(EXIT_FAILURE, "Cannot send packet. Aborting");
  }
  return;
}

static void recv_multicast_reply(
    int fd,
    int timeout)
{
  struct sockaddr_in rcv;
  struct test_packet *pkt;
  struct test_result *r;
  char buf[MAX_PKT_SZ];
  int rc, slen=sizeof(rcv);
  char zbuf[MAX_PKT_SZ];
  memset(buf, 0, sizeof(buf));

  alarm(timeout);
  config.last_seq = -1;

  while (1) {
    rc = recvfrom(fd, buf, MAX_PKT_SZ, 0, (struct sockaddr *)&rcv, &slen);
    if (rc <= 0) {
      if (errno == EINTR)
        return;
      err(EXIT_FAILURE, "Could not receive packet");
    }

    pkt = (struct test_packet *)pkt;
    r = get_result(pkt->seqno);
    /* Put the time we got it in */
    memcpy(&r->recvtime, &pkt->recvtime, sizeof(r->recvtime));

    /* Copy the source address in */
    memcpy(&r->sources[r->naddrs], &rcv, slen);
    r->rep_pktsz = rc;
    if (r->rep_pktsz != config.packet_sz) {
      r->malformed = true;
      continue;
    }

    /* If the padding is not zero in the packet, its malformed */
    if (memcmp(buf+sizeof(struct test_packet), zbuf, 
           rc-(sizeof(struct test_packet))) != 0) {
      r->malformed = true;
      continue;
    }

    /* If this sequence number is not greater than the lasst, it
       arrived out of sequence */
    if (config.last_seq >= ntohl(pkt->seqno))
      r->out_of_sequence = true;

    config.last_seq = ntohl(pkt->seqno);
  }
}

static void handle_alarm(
    int sig)
{
  /* Does nothing but interrupts the process */
  return;
}

static double get_timediff(
    struct timespec *now,
    struct timespec *then)
{
  double val;

  val = (float)(now->tv_sec - then->tv_sec);
  val += ((float)(now->tv_nsec - then->tv_nsec)/1000000000);
  return val;
}

int main(
    int argc,
    char **argv)
{
  int rc;
  int timer = -1;
  int socket = -1;
  int poll = -1;

  int seqno, i,j;
  double rtime;
  char from[20*MAX_SOURCES];
  char status[64];

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = handle_alarm;
  sigaction(SIGALRM, &act, NULL);

  parse_config(argc, argv);

  res = calloc(config.num_packets, sizeof(struct test_result));
  if (!res)
    err(EXIT_FAILURE, "Cannot allocate memory for test results");

  socket = create_multicast_socket(config.iface, config.mcast_addr, config.mcast_port);

  if (config.listen_mode) 
    recv_multicast(socket);
  else {
    send_multicast(socket);
    recv_multicast_reply(socket, 5);
  }

  /* Test the result */
  for (i=0; i < config.num_packets; i++) {
    seqno = 0;
    memset(from, 0, sizeof(from));
    rtime = 0.;
    memset(status, 0, sizeof(status));

    seqno = htonl(res[i].seqno);
    for (j=0; j < res[i].naddrs; j++) {
      strcat(from, inet_ntoa(res[i].sources[j].sin_addr));
      strcat(from, " ");
    }
    if (res[i].naddrs == 0)
      rtime = 0.;
    else
      rtime = get_timediff(&res[i].recvtime, &res[i].sendtime);

    if (res[i].naddrs == 0) {
      strcat(status, "FAIL: LOST");
      goto printit;
    }
    if (res[i].malformed) {
      strcat(status, "FAIL: MALFORMED");
      goto printit;
    }
    if (res[i].out_of_sequence) {
      strcat(status, "FAIL: OUT OF SEQUENCE");
      goto printit;
    }
    if (status[0] == 0) {
      strcat(status, "OK");
      goto printit;
    }
    
  printit:
    printf("Sequence Number: %d, "
           "Response from: %s, "
           "Response time: %f, "
           "Status: %s\n",
           seqno, from, rtime, status);
  }

  exit(0);
}

