#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <err.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>

#include <openssl/sha.h>

#define BUILDDATE   "2016-07-11"
#define MULTIPLIER  5
#define MAX_GRACE   120
#define MAX_PPS     200000
#define MAX_PACKETS INT32_MAX
/* Whatever the MTU is minus some bytes */
#define MIN_PKT_SZ  20
#define MAX_PKT_SZ  1450

// Defaults
#define PORT_DEFAULT       "7777"
#define PACKETSIZE_DEFAULT 5
#define PPS_DEFAULT        5
#define GRACE_DEFAULT      2

struct {
  char *port;
  char *dest;
  struct sockaddr_in *addr;
  int addrlen;
  int32_t pps;
  int32_t numpks;
  int16_t sz;
  int32_t grace;
  bool reflect;
} config;

typedef struct packet_info {
  char checksum_sent[SHA_DIGEST_LENGTH];
  char checksum_rcvd[SHA_DIGEST_LENGTH];
  int rcv_len;
  int32_t rcv_order;
  int32_t index;
  struct timespec sendtime;
  struct timespec recvtime;
} packet_info_t;

bool printhdr = true;
int recvfd = -1;
int sendfd = -1;

packet_info_t *packets = NULL;

static float timediff(
    struct timespec *now,
    struct timespec *then)
{
  float val;

  val = (float)(now->tv_sec - then->tv_sec);
  val += ((float)(now->tv_nsec - then->tv_nsec)/1000000000);
  return val;
}


static void print_usage(
    char *progname)
{
  printf("Usage: %s [OPTION] (reflect|HOSTNAME)\nTry '%s --help' "
         "for more information.\n", progname, progname);
}

static void print_help(
    char *progname)
{
  printf("Usage: %s [OPTION] (reflect|HOSTNAME)\n"
         "Derive the maximum stable packets per second (to 99th percentile) of a\n"
         "destination.\n"
         "Example: %s localhost\n\n"
         "Options:\n"
         " -h    --help          print this help\n"
         " -g    --grace         cooldown period between tests in seconds. (default: 5)\n"
         " -p    --port          port to connect to and listen on (default: 7777)\n"
         " -s    --payload-size  size of packets to deliver (default: 25)\n"
         " -P    --pps           initial packets per second (default: 5)\n"
         "\n"
         "This program attempts to send UDP packets out to a reflecting version of this\n"
         "program at incrasing rates. The purpose is to determine what a reliable\n"
         "packets per second rating is for a destination.\n"
         "\n"
         "Passing \"reflect\" as a single argument causes the program to go into\n"
         "reflection mode which will simply echo back packets it receives as fast as it\n"
         "can.\n"
         "\n"
         "A typical use case would involve setting up a reflector at one end. Then\n"
         "connecting to that destination on the other peer using this program in\n"
         "standard mode\n"
         "\n"
         "The process can perform a (pretty useless) selftest if you use localhost\n"
         "as the first parameter. No reflector is required.\n"
          "\n"
         "Note: The proces listens on the port you send to as well. In order to get\n"
         "the software to work properly a firewall rule both ways needs completing.\n"
         "\n"
         "Different rate limiting systems (I.E token bucket) limit on on packets and\n"
         "size, so test results will likely vary depending on the size of the payload.\n"
         "Typically speaking, the lower the payload the more packets per second you\n"
         "get.\n"
          "\n\n"
         "Written by Matthew Ife (matthew.ife@armor.com) Build date: %s\n"
         "Bugs are included at no extra price.\n"
         ,progname, progname, BUILDDATE);
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
    {"grace", required_argument, 0, 'g'},
    {"port", required_argument, 0, 'p'},
    {"payload-size", required_argument, 0, 's'},
    {"pps", required_argument, 0, 'P'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0 ,0}
  };

  while (1) {
    c = getopt_long(argc, argv, "hp:s:g:P:", loptions, &optidx);
    if (c < 0)
      break;

    switch(c) {

      case 'p':
      if (config.port)
        goto duplicate;
      config.port = strdup(optarg);
      if (!config.port)
        goto syserr;
      break;

      case 's':
      if (config.sz > 0)
        goto duplicate;
      config.sz = atoi(optarg) - 20;
      if (config.sz < MIN_PKT_SZ ||
          config.sz >= MAX_PKT_SZ) {
        err(EXIT_FAILURE, "Packet size must be between %d and %d bytes",
            MIN_PKT_SZ, MAX_PKT_SZ);
      }
      break;

      case 'P':
      if (config.pps > 0)
        goto duplicate;
      config.pps = atoi(optarg);
      if (config.pps < 1 || config.pps > MAX_PPS)
        err(EXIT_FAILURE, "Packets per second must be between %d and %d",
            1, MAX_PPS);
      break;

      case 'h':
      print_help(argv[0]);
      exit(1);
      break;

      case 'g':
      if (config.grace > 0)
        goto duplicate;
      config.grace = atoi(optarg);
      if (config.grace <=0 || config.grace > MAX_GRACE) {
        err(EXIT_FAILURE, "Grace time must be between 1 and %d", MAX_GRACE);
      }
      break;
    }
  }

  if (!config.port) {
    config.port = strdup(PORT_DEFAULT);
    if (!config.port)
      goto syserr;
  }
  if (!config.pps)
    config.pps = PPS_DEFAULT;
  if (!config.numpks)
    config.numpks = config.pps * MULTIPLIER;
  if (!config.sz)
    config.sz = PACKETSIZE_DEFAULT;
  if (!config.grace)
    config.grace = GRACE_DEFAULT;

  config.reflect = false;


  /* Process mandatory argument */
  if (argc-optind == 1) {
    if (strncmp(argv[optind], "reflect", 7) != 0) {
      config.dest = strdup(argv[optind]);
      if (!config.dest)
        err(EXIT_FAILURE, "Memory allocation problem");
    }
    else {
      config.reflect = true;
    }
  }
  else {
    fprintf(stderr, "Expect one parameter\n");
    print_usage(argv[0]);
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


static void create_udp_sockets(
    void)
{
  int c = -1;
  int s = -1;
  int rc;
  struct addrinfo *ai, *ai2, hints;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  rc = getaddrinfo(config.dest, config.port, &hints, &ai);
  if (rc != 0)
    errx(EXIT_FAILURE, "Cannot resolve address %s: %s", config.dest, gai_strerror(rc));

  c = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (!c)
    err(EXIT_FAILURE, "Cannot create client socket");

  hints.ai_flags = AI_PASSIVE;
  rc = getaddrinfo(NULL, config.port, &hints, &ai2);
  if (rc != 0)
    errx(EXIT_FAILURE, "Cannot resolve address: %s: %s", config.dest, gai_strerror(rc));

  s = socket(ai2->ai_family, ai2->ai_socktype, ai2->ai_protocol);
  if (!s)
    err(EXIT_FAILURE, "Cannot create server socket");
  if (bind(s, ai2->ai_addr, ai2->ai_addrlen) < 0)
    err(EXIT_FAILURE, "Cannot bind to socket");

  config.addr = (struct sockaddr_in *)ai->ai_addr;
  config.addrlen = ai->ai_addrlen;
  freeaddrinfo(ai2);
  sendfd = c;
  recvfd = s;

  return;
}


static packet_info_t * generate_packets(
    void)
{
  int i;
  char buffer[MAX_PKT_SZ];

  SHA_CTX sha;

  packet_info_t *packet;
  packet_info_t *data = NULL;
  size_t memsz = (config.numpks * sizeof(packet_info_t)) +
                 (config.numpks * config.sz);

  data = mmap(NULL, memsz, PROT_READ|PROT_WRITE,
              MAP_ANONYMOUS|MAP_SHARED, -1, 0);

  if (data == MAP_FAILED)
    err(EXIT_FAILURE, "Mapping attempt failed");

  memset(buffer, 'A', MAX_PKT_SZ);
  /* Iterate over each packet and prepare what can be prepared now */
  for (i=0; i < config.numpks; i++) {
    SHA1_Init(&sha);
    packet = &data[i];
    packet->rcv_order = -1;
    packet->rcv_len = 0;
    packet->index = i;

    SHA1_Update(&sha, &packet->index, sizeof(packet->index));
    SHA1_Update(&sha, buffer, config.sz);
    SHA1_Final(packet->checksum_sent, &sha);
  }

  return data;
}


static void send_pps(
    void)
{
  int rc;
  char buffer[MAX_PKT_SZ];
  char *b = buffer;
  struct timespec ts = {0,0};
  struct itimerspec iter;
  int freq = 1000000000 / config.pps;
  sigset_t set;
  int total = 0;

  packet_info_t *p;

  sigemptyset(&set);
  sigaddset(&set, SIGALRM);

  if (config.pps == 1) {
    iter.it_interval.tv_sec = 1;
    iter.it_interval.tv_nsec = 0;
    iter.it_value.tv_sec = 1;
    iter.it_value.tv_nsec = 0;
  }
  else {
    iter.it_interval.tv_sec = 0;
    iter.it_interval.tv_nsec = freq;
    iter.it_value.tv_sec = 0;
    iter.it_value.tv_nsec = freq;
  }

  memset(buffer, 'A', MAX_PKT_SZ);

  /* Block the signal handler as a default */
  if (sigprocmask(SIG_BLOCK, &set, NULL) < 0)
    err(EXIT_FAILURE, "Cannot mask signals");

  /* Create and set the timer */
  timer_t timer;
  if (timer_create(CLOCK_MONOTONIC, NULL, &timer) < 0)
    err(EXIT_FAILURE, "Cannot create timer");

  if (timer_settime(timer, 0, &iter, NULL) < 0)
    err(EXIT_FAILURE, "Cannot set timer");

  while (true) {
    if (sigwaitinfo(&set, NULL) < 0)
      err(EXIT_FAILURE, "Cannot consume on signal handler");

    /* Construct packet */
    p = &packets[total];
    clock_gettime(CLOCK_MONOTONIC, &p->sendtime);
    memcpy(b, &p->index, sizeof(p->index));
    b += sizeof(p->index);
    memcpy(b, &p->sendtime, sizeof(p->sendtime));
    b += sizeof(p->sendtime);
    b += config.sz;

    /* Push out he buffer */
    rc = sendto(sendfd, buffer, (b-buffer), MSG_NOSIGNAL, config.addr, config.addrlen);
    if (rc < 0)
      warn("Cannot send packet");
    else if (rc != (b-buffer))
      warnx("Incomplete packet send: %d of %d bytes sent only", rc, (b-buffer));

    total++;

    if (total >= config.numpks)
      break;
    b = buffer;
  }

  /* Disarm timer */
  memset(&iter, 0, sizeof(iter));
  if (timer_settime(timer, 0, &iter, NULL) < 0)
    err(EXIT_FAILURE, "Cannot disarm timer");

  /* Consumes pending signals */
  while (sigtimedwait(&set, NULL, &ts) == SIGALRM)

  /* Unmask set */
  if (sigprocmask(SIG_UNBLOCK, &set, NULL) < 0)
    err(EXIT_FAILURE, "Cannot set signal handlers");

  /* Wait the grace period */
  sleep(config.grace);
}


static void * recv_pps(
    void *nill)
{
  char buffer[MAX_PKT_SZ];
  char *b;
  struct sockaddr_in addr;
  int rc;
  int len;
  int32_t counter = 0;
  int rcv_sz = (sizeof(struct timespec) + sizeof(int) + config.sz);
  int32_t idx;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);

  packet_info_t *pkt;
  SHA_CTX sha;

  /* Setup the signal mask */
  pthread_sigmask(SIG_BLOCK, &set, NULL);

  memset(buffer, 0, MAX_PKT_SZ);

  while (1) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    rc = recvfrom(recvfd, buffer, rcv_sz, 0, &addr, &len);
    if (rc < 0)
      err(EXIT_FAILURE, "Cannot receive");
    if (rc != rcv_sz) {
      printf("No gobble gobble: rc = %d, rcv_sz = %d\n", rc, rcv_sz);
      continue;
    }
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    b = buffer;
    memcpy(&idx, b, sizeof(idx));
    if (idx < 0 || idx > config.numpks)
      warn("Unknown packet recieved. Discarded");
    b += sizeof(idx);

    /* Fetch packet and add when we got it */
    pkt = &packets[idx];
    pkt->rcv_order = counter;
    pkt->rcv_len = rc;

    /* Copy the timestamp into the record */
    clock_gettime(CLOCK_MONOTONIC, &pkt->recvtime);
    b += sizeof(pkt->recvtime);

    /* Calculate sha sum */
    SHA1_Init(&sha);
    SHA1_Update(&sha, &idx, sizeof(idx));
    SHA1_Update(&sha, b, (rc - sizeof(idx) - sizeof(pkt->recvtime)));
    SHA1_Final(pkt->checksum_rcvd, &sha);

    pthread_testcancel();

    counter++;
  }
}


static float generate_report(
    void)
{
  packet_info_t *p = packets;
  int pkts_missing = 0;
  int pkts_corrupt = 0;
  int pkts_ok = 0;
  float total_time = 0.0;
  float bytes = 0.0;
  float diff = 0.0;
  int i;
  struct timespec first = {INT32_MAX,INT32_MAX};
  struct timespec last = {0,0};
  float pps_ratio, hit_ratio;

  for (i=0; i < config.numpks; i++) {
    p = &packets[i];

    if (p->rcv_order == -1) {
      pkts_missing++;
      continue;
    }
    else if (memcmp(p->checksum_sent, p->checksum_rcvd, SHA_DIGEST_LENGTH) != 0) {
      //printf("%s, %s\n", p->checksum_sent, p->checksum_rcvd);
      pkts_corrupt++;
      continue;
    }

    pkts_ok++;

    bytes += p->rcv_len;
    total_time += timediff(&p->recvtime, &p->sendtime);

    /* Find the processing time */
    if (p->recvtime.tv_sec < first.tv_sec ||
         (p->recvtime.tv_sec == first.tv_sec &&
          p->recvtime.tv_nsec < first.tv_nsec)) {
      first.tv_sec = p->recvtime.tv_sec;
      first.tv_nsec = p->recvtime.tv_nsec;
    }
    if (p->recvtime.tv_sec > last.tv_sec ||
         (p->recvtime.tv_sec == last.tv_sec &&
          p->recvtime.tv_nsec > last.tv_nsec)) {
      last.tv_sec = p->recvtime.tv_sec;
      last.tv_nsec = p->recvtime.tv_nsec;
    }
  }

  diff = timediff(&last, &first);

  if (printhdr) {
    printf("%8s%8s%10s%10s%11s%10s%12s%13s%11s%15s\n", "Sent", "Packets", "Packets", "Packets",
          "Recieved", "Latency", "Mbits", "Sent", "Hit/Miss", "Sent/Rcvd PPS");
    printf("%8s%8s%10s%10s%11s%10s%12s%13s%11s%15s\n", "PPS", "Rcvd", "Corrupt", "Missing",
          "Time", "Seconds", "Seconds", "PPS", "Percent", "Percent");
    printhdr = false;
  }
  printf("%8d%8d%10d%10d", config.pps, pkts_ok, pkts_corrupt, pkts_missing);
  if (total_time <= 0.0)
    printf("%11s%10s%12s%13s%11s%15s\n", "NaN", "NaN", "Nan", "NaN", "0", "0");
  else
    printf("%11.3f%10.3f%12.3f%13.3f%11.2f%15.2f\n", diff,
          (total_time / (float)pkts_ok),
          (((bytes*8) / diff)/1000000), (float)pkts_ok / diff,
          (float)pkts_ok / ((float)pkts_ok + (float)pkts_missing) * 100,
          (((float)pkts_ok / diff) / config.pps) * 100);

  pps_ratio = (((float)pkts_ok / diff) / config.pps);
  hit_ratio = (float)pkts_ok / ((float)pkts_ok + (float)pkts_missing);
  return (pps_ratio + hit_ratio) / 2;
}


void do_reflection(
    void)
{
  /* We setup the sockets first */
  char buffer[MAX_PKT_SZ];
  char *b = buffer+sizeof(int32_t);
  int rc;
  int socklen;
  struct timespec ts;
  struct addrinfo *ai, hints;
  struct sockaddr_in src;

  memset(&src, 0, sizeof(src));
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  rc = getaddrinfo(NULL, config.port, &hints, &ai);
  if (rc != 0)
    errx(EXIT_FAILURE, "Cannot resolve address %s: %s", config.dest, gai_strerror(rc));

  recvfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (recvfd < 0)
    err(EXIT_FAILURE, "Cannot create socket");
  if (bind(recvfd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EXIT_FAILURE, "Cannot bind to socket");


  sendfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (sendfd < 0)
    err(EXIT_FAILURE, "Cannot create client socket");

  /* Now we wait for packets to arrive and send them to their destination as
   *  quickly as possible */
  while (1) {
    rc = recvfrom(recvfd, buffer, MAX_PKT_SZ,
                  0, &src, &socklen);
    if (rc < 0)
      err(EXIT_FAILURE, "Cannot recieve packet");

    src.sin_port = ((struct sockaddr_in *)(ai->ai_addr))->sin_port;
    rc = sendto(sendfd, buffer, rc, MSG_NOSIGNAL, &src, sizeof(src));
    if (rc < 0)
      err(EXIT_FAILURE, "Cannot send packet");
  }
}


int main(
    int argc,
    char **argv)
{
  bool go = true, tune = false;
  int rc;
  pthread_t consumer;
  /* Parse the configuration */
  parse_config(argc, argv);
  float res;

  float hit = 0;

  if (config.reflect) {
    printf("Reflecting..\n");
    do_reflection();
    exit(0);
  }

  /* Create sockets */
  create_udp_sockets();

  while (go) {
    /* Generate the data that will be used in this configuration */
    packets = generate_packets();

    /* Split the process in two. One is the consumer, the other is the sender */
    rc = pthread_create(&consumer, NULL, recv_pps, NULL);
    if (rc)
      errx(EXIT_FAILURE, "Cannot create thread: %s", strerror(rc));

    /* sender process */
    send_pps();

    /* Cancel the receiver */
    rc = pthread_cancel(consumer);
    if (rc)
      err(EXIT_FAILURE, "Cannot cancel thread");

    pthread_join(consumer, NULL);

    /* Generate report */
    res = generate_report();

    /* Reset the original state. Modify the next new number
     * of packets per second based off of the results of
     * this run. */
    munmap(packets, (config.numpks * sizeof(packet_info_t))
                    + (config.numpks * config.sz));

    /* We raise the pps level up 3 times what we had before, when
     * we've not missed 99% of our packets and our tested pps
     * is 99% or more of our actual pps. */
    if (res > 0.99 && tune == false)
      config.pps = config.pps * 3;
    else {
      /* If we hit tune mode, then we raise our pps by
       * using the 'res' as the factor to retune the value */
      if (res > 0.99)
        hit += res;
      else
        hit = 0.0;
      config.pps = config.pps * res;
      tune = true;
    }
    config.numpks = (config.pps * MULTIPLIER);
    /* If we hit our maximum allowed PPS, or - we get a
     * 99% result 6 times in a row, we quit as the best pps
     * estimate for that packet length */
    if (config.pps > MAX_PPS || hit > 5.0)
      go = false;
  }
  exit(0);
}
