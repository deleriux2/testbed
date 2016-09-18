#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <string.h>
#include <signal.h>

#include <err.h>
#include <sysexits.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sched.h>
#include <netdb.h>

#define REQSZ 8192
#define TIMEOUT 3
#define SERV_FILE "/tmp/hello_world.html"
#define SERVERPORT "40001"
#define MAX_CONCURRENCY 50000

/* Vigilance is needed to atomically increment/decrement
 * some values, these macros take care of this
 */
#define up(a) \
  while (a == __sync_add_and_fetch(&a, 1)) \
    sched_yield();

#define down(a) \
  while (a == __sync_sub_and_fetch(&a, 1)) \
    sched_yield();

struct buffer {
  int fd;
  int offset;
  int sz;
  char buf[REQSZ];
};

struct callback {
  int fd;
  time_t last;
  int events;
  void *data;
  int (*cb)(int,int,void *);
};

time_t now;
int timer = -1;
int serverfd = -1;
int poll = -1;
struct callback *callbacks[MAX_CONCURRENCY];

static struct callback * get_cb_by_fd(
    int fd)
{
  struct callback *c = NULL;
  int i;
  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (callbacks[i] && callbacks[i]->fd == fd) {
      c = callbacks[i];
      return c;
    }
  }
  return NULL;
}

static struct callback * get_next_cb(
    void)
{
  int i;
  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (callbacks[i] == NULL) {
      callbacks[i] = malloc(sizeof(struct callback));
      if (!callbacks[i])
        return NULL;
      return callbacks[i];
    }
  }
  return NULL;
}


void free_cb(
    struct callback *cb)
{
  int i;
  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (cb == callbacks[i]) {
      if (callbacks[i]->data) {
        free(callbacks[i]->data);
      }
      callbacks[i] = NULL;
    }
  }
}

int mod_poll_fd(
    int pollfd,
    int fd,
    int events,
    int (*cb)(int,int,void*),
    void *data)
{
  int i;
  struct epoll_event ev;
  struct callback *c = NULL;

  /* Get callback via fd */
  c = get_cb_by_fd(fd);
  if (!c)
    goto fail;

  c->events = events;
  c->data = data;
  c->cb = cb;
  ev.events = events;
  ev.data.ptr = c;

  if (epoll_ctl(pollfd, EPOLL_CTL_MOD, fd, &ev) < 0)
    goto fail;

  return 0;

fail:
  return -1;
  
}


/* Add fd to poll set */
int add_poll_fd(
    int pollfd,
    int fd,
    int events,
    int (*cb)(int,int,void*),
    void *data)
{
  int e;
  struct epoll_event ev;
  struct callback *c;

  c = get_next_cb();
  if (!c)
    goto fail;

  c->fd = fd;
  c->events = events;
  c->data = data;
  c->cb = cb;
  c->last = now;
  ev.events = events;
  ev.data.ptr = c;

  if (epoll_ctl(pollfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    goto fail;

  return 0;

fail:
  e = errno;
  if (c)
    free(c);
  errno = e;
  return -1;
}

static int setup_timer()
{
  int fd = -1;
  fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (fd < 0)
    err(EX_OSERR, "Timerfd did not get created");

  struct itimerspec itm = { {TIMEOUT, 0}, {TIMEOUT, 0} };
  if (timerfd_settime(fd, 0, &itm, NULL) < 0)
    err(EX_OSERR, "Could not arm the timer");

  return fd;
}

/* Convenience function to setup epoll */
static int setup_epoll()
{
  int fd = -1;
  fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0)
    err(EX_OSERR, "Epoll setup failed");

  return fd;
}


/* Setup ulimits to ensure the number of connections 
 * we handle is supported
 */
static void set_limits(
    int limit)
{
  struct rlimit nfile;

  if (getrlimit(RLIMIT_NOFILE, &nfile) < 0)
    err(EX_OSERR, "Cannot retrive open file limit");

  /* Change limits */
  nfile.rlim_cur = MAX_CONCURRENCY + 200;
  nfile.rlim_max = MAX_CONCURRENCY + 200;

  if (nfile.rlim_cur > nfile.rlim_max)
    errx(EX_SOFTWARE, "Cannot set max open file soft limit to %d"
                      " when hard limit is %d",
                       nfile.rlim_cur, nfile.rlim_max);

  if (setrlimit(RLIMIT_NOFILE, &nfile) < 0)
    err(EX_OSERR, "Cannot set open file limit");
}

/* Sets up a bindable tcp connection */
static int tcp_server(
    char *port)
{
  int fd, rc, yes=1;
  struct addrinfo *ai = NULL;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));

  /* Create a usable socket */
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = INADDR_ANY|AI_PASSIVE;  
  rc = getaddrinfo(NULL, port, &hints, &ai);
  if (rc)
    errx(EX_UNAVAILABLE, "Cannot assign requested address: %s", gai_strerror(rc));

  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0)
    err(EX_OSERR, "Cannot create socket");

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
    err(EX_OSERR, "Cannot set socket option");

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
    err(EX_OSERR, "Cannot set socket option");

  if (fcntl(fd, F_SETFL, O_NONBLOCK))
    err(EX_OSERR, "Cannot set server socket nonblock");

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EX_OSERR, "Cannot bind to address");

  if (listen(fd, 125) < 0)
    err(EX_OSERR, "Cannot listen on socket");

  freeaddrinfo(ai);
  return fd;
}


int disconnect(
    int fd)
{
  struct callback *c;
  if (fd == serverfd)
    return;

  c = get_cb_by_fd(fd);
  
  shutdown(fd, SHUT_RDWR);
  free_cb(c);
  close(fd); 
}


int send_file(
    int fd,
    int events,
    void *data)
{
  struct buffer *buf = (struct buffer *)data;
  int sz;

  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  sz = sendfile(fd, buf->fd, buf->offset, (buf->sz - buf->offset));

  if (sz < 0)
    return -1;

  buf->offset += sz;
  if (buf->offset == buf->sz) {
    close(buf->fd);
    return -1;
  }

  return 0; 
}


int open_file(
    int fd,
    int events,
    void *data)
{

  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  struct buffer *buf = malloc(sizeof(*buf));
  struct stat st;

  if (!buf)
    return -1;

  memset(buf, 0, sizeof(*buf));

  /* Inefficient */
  if (stat(SERV_FILE, &st) < 0) {
    free(buf);
    return -1;
  }

  buf->sz = st.st_size;
  buf->fd = open(SERV_FILE, O_RDONLY);
  if (buf->fd < 0) {
    free(buf);
    return -1;
  }

  if (mod_poll_fd(poll, fd, EPOLLOUT, send_file, buf) < 0)
    return -1;

  return 0;
}


int send_header(
    int fd,
    int events,
    void *data)
{
  struct buffer *buf = (struct buffer *)data;
  int sz;

  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  sz = send(fd, (buf->buf + buf->offset), (buf->sz - buf->offset), MSG_NOSIGNAL);
  if (sz < 0)
    return -1;

  buf->offset += sz;
  if (buf->offset == buf->sz) {
    free(data);
    if (mod_poll_fd(poll, fd, EPOLLOUT, open_file, NULL) < 0)
      return -1;
  }

  return 0;  
}


int prep_header(
    int fd,
    int events,
    void *data)
{
  struct buffer *buf = malloc(sizeof(*buf));
  int *sz = (int *)data;

  if (!buf)
    return -1;

  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  memset(buf, 0, sizeof(*buf));
  buf->sz = snprintf(buf->buf, 8192, "HTTP 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"
                             "Connection: close\r\n", *sz);

  free(data);
  if (mod_poll_fd(poll, fd, EPOLLOUT, send_header, buf) < 0)
    return -1;

  return 0;
}


int stat_file(
    int fd,
    int events,
    void *data)
{
  struct stat st;
  int *sz;

  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  if (stat(SERV_FILE, &st) < 0)
    return -1;

  sz = malloc(sizeof(*sz));
  if (!sz)
    return -1;
  *sz = st.st_size;

  if (mod_poll_fd(poll, fd, EPOLLOUT, prep_header, sz) < 0)
    return -1;

  return 0;
}


int read_request(
    int fd,
    int events,
    void *data)
{
  int sz;
  char *p;
  struct buffer *buf = (struct buffer *) data;

  /* Read the buffer */
  sz = recv(fd, (buf->buf+buf->offset), (REQSZ-buf->offset), 0);
  if (sz < 0)
    return -1;
  else if (sz == 0)
    return -1;

  buf->offset += sz;
  p = (buf->buf + (buf->offset-4));

  if (strncmp(p, "\r\n\r\n", 4) == 0) {
    free(buf);
    if (mod_poll_fd(poll, fd, EPOLLOUT, stat_file, NULL) < 0)
      return -1;
  }

  return 0;
}    


int prep_request(
    int fd,
    int events,
    void *data)
{
  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  struct buffer *buf = NULL;
  buf = malloc(sizeof(struct buffer));
  if (!buf)
    return -1;

  if (mod_poll_fd(poll, fd, EPOLLOUT, read_request, buf) < 0)
    return -1;

  return 0;
}

/* Accept a new connection */
int accept_conn(int fd, 
    int events, 
    void *data)
{
  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  int cli;
  cli = accept4(fd, NULL, 0, SOCK_NONBLOCK);
  if (cli < 0) {
    warn("Cannot accept connection");
    return 0;
  }
  if (add_poll_fd(poll, cli, EPOLLIN, prep_request, NULL) < 0)
    disconnect(fd);

  return 0;
}

int read_timer(
    int fd,
    int events,
    void *data)
{
  unsigned long long u64;
  int i;
  int active=0;
  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  if (read(fd, &u64, sizeof(u64)) < 0)
    err(EX_OSERR, "Timer has failed");

  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (callbacks[i] && callbacks[i]->fd == timer) continue;
    else if (callbacks[i] && callbacks[i]->fd == serverfd) continue;
    else if (callbacks[i] && (now - callbacks[i]->last) > TIMEOUT) {
      printf("Connection timed out: %d\n", callbacks[i]->fd);
      disconnect(callbacks[i]->fd);
    }
    else if (callbacks[i] && callbacks[i]->fd) {
      active++;
    }
  }
  printf("Active: %d\n", active);
  return 0;
}

int main(void)
{
  memset(callbacks, 0, sizeof(*callbacks));

  /* Setup the listening port */
  int fd = tcp_server(SERVERPORT);
  serverfd = fd;
  struct epoll_event evs[MAX_CONCURRENCY];
  poll = setup_epoll();
  timer = setup_timer();

  /* Set the limits to match our max servicable requests */
  set_limits(MAX_CONCURRENCY);

  if (add_poll_fd(poll, fd, EPOLLIN, accept_conn, NULL) < 0)
    err(EX_OSERR, "Cannot add serverfd to set");

  if (add_poll_fd(poll, timer, EPOLLIN, read_timer, NULL) < 0)
    err(EX_OSERR, "Could not add timerfd to set");

  /* Go into event loop */
  int num, i;
  int savednum = 0;
  struct callback *cb;
  while (1) {
    memset(evs, 0, sizeof(*evs));

    num = epoll_wait(poll, evs, MAX_CONCURRENCY, 1000);
    if (num < 0) {
      if (errno == EINTR)
        continue;
    }

    now = time(NULL);
    for (i=0; i < num; i++) {
      cb = (struct callback *)evs[i].data.ptr;
      cb->last = now;
      if (cb->cb) {
        /* Invoke the callback */
        if (cb->cb(cb->fd, evs[i].events, cb->data) < 0)
          disconnect(cb->fd);
      }
      else {
        disconnect(cb->fd);
      }
    }

    if (num > savednum) {
      savednum = num;
      printf("Concurrency: %d\n", savednum);
    }
    
  }

  exit(0);
}
