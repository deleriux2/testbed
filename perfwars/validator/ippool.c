#include "ippool.h"
#include <poll.h>
#include <ifaddrs.h>

#include <netinet/in.h>
#include <arpa/inet.h>

static int ippool_get_default_iface(
    char *hostname,
    char *port,
    char *iface,
    int len)
{
  struct addrinfo *ai=NULL, hints;
  struct sockaddr_in6 addr, *dst;
  unsigned char *src, *cmp;
  struct ifaddrs *ifs=NULL, *tmp;
  struct pollfd pfd;
  int rc;
  int eno=110;
  int fd = -1;
  int found=0;
  socklen_t slen=sizeof(struct sockaddr_in6);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo(hostname, port, &hints, &ai);
  if (rc != 0) {
    warnx("Cannot resolve hostname: %s", 
          gai_strerror(rc));
    goto fail;
  }

  /* Connect with a test socket */
  fd = socket(ai->ai_family, ai->ai_socktype|SOCK_NONBLOCK, ai->ai_protocol);
  if (fd < 0) {
    warn("Cannot create test socket");
    goto fail;
  }

  if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
    if (errno == EINPROGRESS) {
      pfd.fd = fd;
      pfd.events = POLLOUT;
      if ((rc = poll(&pfd, 1, 2000)) < 0) {
        warn("Cannot poll connecting socket");
        goto fail;
      }

      if (rc == 0) {
        warnx("Cannot poll connecting socket: Timeout");
        goto fail;
      }

      rc = sizeof(int); 
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &eno, &rc) < 0) {
        warn("Cannot connect with test socket");
        goto fail;
      }

      if (eno != 0) {
        errno = eno;
        warn("Cannot connect with test socket");
        goto fail;
      }
    }
    else {
      warn("Cannot connect with test socket");
      goto fail;
    } 
  }

  /* Derive the source IP address of our connection */
  if (getsockname(fd, (struct sockaddr *)&addr, &slen) < 0) {
    warn("Could not obtain address of test socket");
    goto fail;
  }
  close(fd);
  freeaddrinfo(ai);
  fd = -1;
  ai = NULL;
  src = addr.sin6_addr.s6_addr;

  /* Fetch a list of all the interfaces */
  if (getifaddrs(&ifs) < 0) {
    warnx("Cannot get a list of interfaces");
    goto fail;
  }

  /* Find our IP address and relay the interface it lives on */
  tmp = ifs;
  while (tmp) {
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET6) {
      dst = (struct sockaddr_in6 *)tmp->ifa_addr;
      cmp = dst->sin6_addr.s6_addr;
      if (memcmp(cmp, src, 16) == 0) {
        strncpy(iface, tmp->ifa_name, len);
        found=1;
        break;
      }
    }
    tmp = tmp->ifa_next;
  }
  if (!found) {
    warnx("Cannot fetch interface to use");
    goto fail;
  }

  freeaddrinfo(ai);
  freeifaddrs(ifs);
  return 0;
  
fail:
  freeaddrinfo(ai);
  if (fd < 0)
    close(fd);
  if (ifs)
    freeifaddrs(ifs);
  return -1;
}

ippool_t * ippool_init_dst(
    char *desthost,
    char *testport)
{
  struct addrinfo *ai=NULL, *tmp, hints;
  ippool_t *ipp=NULL;
  int rc;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo(desthost, testport, &hints, &ai);
  if (rc) {
    warnx("Cannot resolve hostname: %s", gai_strerror(rc));
    goto fail;
  }

  rc = 0;
  tmp = ai;
  while (tmp) {
    rc++;
    tmp=tmp->ai_next;
  }

  ipp = malloc(sizeof(ippool_t));
  ipp->current = 0;
  ipp->total = rc;
  ipp->addrs = calloc(rc, sizeof(struct sockaddr_in6));
  pthread_mutex_init(&ipp->lock, NULL);

  rc = 0;
  tmp = ai;
  while (tmp) {
    memcpy(&ipp->addrs[rc], tmp->ai_addr, sizeof(struct sockaddr_in6));
    rc++;
    tmp = tmp->ai_next;
  }

  freeaddrinfo(ai);
  return ipp;

fail:
  if (ipp)
    ippool_destroy(ipp);
  if (ai)
    freeaddrinfo(ai);
  return NULL;
}

ippool_t * ippool_init_src(
    char *desthost,
    char *destport)
{
  char iface[17];
  struct ifaddrs *ifs = NULL, *tmp;
  int count=0;
  ippool_t *ip=NULL;

  memset(iface, 0, 17);
  if (ippool_get_default_iface(desthost, destport, iface, 16) < 0)
    goto fail;

  if (getifaddrs(&ifs) < 0)
    goto fail;

  /* First pass, get a count of valid addresses */
  tmp = ifs;
  while (tmp) {
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET6) {
      if (strncmp(tmp->ifa_name, iface, 16) == 0) {
        count++;
      }
    }
    tmp = tmp->ifa_next;
  }

  /* Now, initialize our structure */
  ip = malloc(sizeof(ippool_t));
  if (!ip)
    goto fail;
  ip->addrs = calloc(count, sizeof(struct sockaddr_in6));
  if (!ip->addrs)
    goto fail;
  ip->current = 0;
  ip->total = count;

  /* Second pass, fill in our structures */
  tmp = ifs;
  count=0;
  while (tmp) {
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET6) {
      if (strncmp(tmp->ifa_name, iface, 16) == 0) {
        memcpy(&ip->addrs[count], tmp->ifa_addr, sizeof(struct sockaddr_in6));
        count++;
      }
    }
    tmp = tmp->ifa_next;
  }

  pthread_mutex_init(&ip->lock, NULL);

  if (ifs)
    freeifaddrs(ifs);
  return ip;

fail:
  ippool_destroy(ip);
  return NULL;
}


void ippool_destroy(
    ippool_t *ip)
{
  if (ip) {
    if (ip->addrs) {
      free(ip->addrs);
    }
    pthread_mutex_destroy(&ip->lock);
  }
}

struct sockaddr_in6 * ippool_next(
    ippool_t *ipp)
{
  struct sockaddr_in6 *in;
  if (ipp->total == 1) {
    return &ipp->addrs[ipp->current];
  }
  else {
    pthread_mutex_lock(&ipp->lock);
    in = &ipp->addrs[ipp->current];
    ipp->current++;
    if (ipp->current >= ipp->total)
      ipp->current = 0;
    pthread_mutex_unlock(&ipp->lock);
  }
  return in;
}
