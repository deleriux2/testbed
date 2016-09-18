/* Multicast test. Determines if two systems are able to multicast to one another.
 * Written my Matthew Ife matthew.a.ife@gmail.com.
 *
 * Should be run on all participating servers to function correctly,
 *
 */

/* System includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

/* For sockets */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>

/* For the timer */
#include <sys/timerfd.h>

/* For polling */
#include <sys/epoll.h>

/* This is the multicast group and port used for this service */

/* Global used for storage of multicast address */
struct sockaddr_in dst;

/* Our sequence number used during sends */
int seqno = 0;

/* Our systems hostname */
char hostn[64];

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

static int arm_timer(
    int seconds)
{
  struct itimerspec ival;
  int fd = -1;

  memset(&ival, 0, sizeof(ival));

  fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  if (fd < 0)
    err(EXIT_FAILURE, "Cannot create timer");

  ival.it_interval.tv_sec = seconds;
  ival.it_interval.tv_nsec = 0;
  ival.it_value.tv_sec = seconds;
  ival.it_value.tv_nsec = 0;

  if (timerfd_settime(fd, 0, &ival, NULL) < 0)
    err(EXIT_FAILURE, "Cannot arm timer");

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
  memset(&dst, 0, sizeof(dst));

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
    err(EXIT_FAILURE, "Cannot bind to device");

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
  dst.sin_family = AF_INET;
  dst.sin_port = portno;
  dst.sin_addr.s_addr = inet_addr(mc_addr);

  return fd;
}

static void process_timer(
   int fd)
{
  /* This does nothing but empties the kernel buffer */
  uint64_t buf;
  if (read(fd, &buf, sizeof(buf)) < 0)
    err(EXIT_FAILURE, "Could not read from timer. This is fatal. Aborting");
  return;
}

static void send_multicast(
    int fd)
{
  char buf[128];
  memset(buf, 0, sizeof(buf));

  snprintf(buf, 127, "%s: sequence no: %d", hostn, seqno++);
  if (sendto(fd, buf, strlen(buf), MSG_NOSIGNAL, (struct sockaddr *)&dst, sizeof(dst)) < 0)
    err(EXIT_FAILURE, "Cannot send message. Aborting");

  printf("> %s\n", buf);
  fflush(stdout);
  return;
}

static void recv_multicast(
    int fd)
{
  struct sockaddr_in rcv;
  int rc = sizeof(rcv);
  char buf[128];
  memset(&rcv, 0, sizeof(rcv));
  memset(buf, 0, sizeof(buf));

  if (recvfrom(fd, buf, 128, 0, (struct sockaddr *)&rcv, &rc) <= 0)
    err(EXIT_FAILURE, "Cannot retrieve packet. Aborting");

  printf("< %s\n", buf);
  fflush(stdout);
  return;
}

int main(
    int argc,
    char **argv)
{
  int rc;
  int timer = -1;
  int socket = -1;
  int poll = -1;
  struct epoll_event ev;

  if (argc < 4)
    errx(EXIT_FAILURE, "Must pass the network interface name you will be using for this test, the multicast address and the multicast port\nE.G. '%s eth0 224.0.0.251 55555'", argv[0]);

  /* Set the hostname buffer */
  memset(hostn, 0, 64);
  if (gethostname(hostn, 64) < 0)
    err(EXIT_FAILURE, "Could not retrieve system hostname");

  socket = create_multicast_socket(argv[1], argv[2], argv[3]);
  timer = arm_timer(1);
  poll = create_poll(timer, socket);

  /* Begin event loop */
  while (1) {
    rc = epoll_wait(poll, &ev, 1, -1);
    if (rc < 0)
      err(EXIT_FAILURE, "Expected an event, but got an error");
    else if (rc == 0) {
      warn("No events but poll returned? Continuing..");
      continue;
    }

    /* If its the timer, process the timer, send a multicast out */
    if (ev.data.fd == timer) {
      process_timer(timer);
      send_multicast(socket);
    }
    if (ev.data.fd == socket) {
      recv_multicast(socket);
    }
  }

  exit(0);
}
