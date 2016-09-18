#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

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
#include <pthread.h>
#include "queue.h"

#define REQSZ 2048
#define TIMEOUT 3
#define SERV_FILE "/tmp/hello_world.html"
#define SERVERPORT "40001"
#define MAX_CONCURRENCY 50000

/* A multiplexing "web" server, demonstrates this model.
 * Scales fairly, testing up to 20000 concurrent connections and
 * 5000 concurrent connections for large transfers

 * Is split into two parts. An event loop controlled by an epoll fd.
 * And a series of worker threads controlled by a queueing implementation.
 *
 * The queueing is special in that we can have the producer wait for the 
 * queue to empty before we resubmit new entries onto the queue.
 * This is because we cannot / do not want to have the epoll fire on events still
 * being worked on.
 * It --may-- be more efficient to remove entries from the epoll when being
 * handled rather than doing this.
 */


pthread_rwlock_t rwlock;
struct buffer {
  int fd;
  int offset;
  int sz;
  int filesize;
  char buf[REQSZ];
};

struct callback {
  int fd;
  time_t last;
  int events;
  void *data;
  int (*cb)(int,int,void *);
  volatile pthread_t who;
};

time_t now;
int timer = -1;
int serverfd = -1;
int poll = -1;
struct callback *callbacks[MAX_CONCURRENCY];


/* Find the callback structure by rotating through
 * the FD
 */
static struct callback * get_cb_by_fd(
    int fd)
{
  struct callback *c = NULL;
  int i;
  /* Must acquire a read lock */
  pthread_rwlock_rdlock(&rwlock);
  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (callbacks[i] && callbacks[i]->fd == fd) {
      c = callbacks[i];
      break;
    }
  }
  pthread_rwlock_unlock(&rwlock);
  return c;
}


/* Obtains the next free callback and mallocs against
 * the discovered pointer. Requires a write lock */
static struct callback * get_next_cb(
    void)
{
  int i;
  /* Must have the write lock for this to work */
  pthread_rwlock_wrlock(&rwlock);
  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (callbacks[i] == NULL) {
      callbacks[i] = malloc(sizeof(struct callback));
      if (!callbacks[i]) {
        goto fail;
      }
      pthread_rwlock_unlock(&rwlock);
      return callbacks[i];
    }
  }

fail:
  pthread_rwlock_unlock(&rwlock);
  return NULL;
}


/* Frees allocated memory for from a callback 
 * Needs a write lock.
 */
void free_cb(
    struct callback *cb)
{
  int i;
  struct buffer *buf;

  if (!cb) return;

  pthread_rwlock_wrlock(&rwlock);
  for (i=0; i < MAX_CONCURRENCY; i++) {
    if (callbacks[i] == cb) {
      if (callbacks[i]->data) {
        buf = (struct buffer *)callbacks[i]->data;
        if (buf->fd >= 0)
          close(buf->fd);
        free(callbacks[i]->data);
      }
      free(callbacks[i]);
      callbacks[i] = NULL;
      break;
    }
  }
  pthread_rwlock_unlock(&rwlock);
}


/* Suspends a polled FD from being triggered */
int suspend_poll_fd(
    int fd)
{
  struct epoll_event ev;
  struct callback *c = NULL;

  c = get_cb_by_fd(fd);
  if (!c)
    goto fail;

  ev.events = 0;
  ev.data.ptr = c;

  if (epoll_ctl(poll, EPOLL_CTL_MOD, fd, &ev) < 0)
    goto fail;

  return 0;

fail:
  return -1;
}

/* Unsuspend a polled fd so it can be triggered again */
int resume_poll_fd(
    int fd)
{
  struct epoll_event ev;
  struct callback *c = NULL;

  c = get_cb_by_fd(fd);
  if (!c)
    goto fail;

  ev.events = c->events;
  ev.data.ptr = c;

  if (epoll_ctl(poll, EPOLL_CTL_MOD, fd, &ev) < 0)
    goto fail;

  return 0;

fail:
  return -1;
}

/* Used to alter the callbacks on an FD */
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

  events |= EPOLLET;

  /* Get callback via fd */
  c = get_cb_by_fd(fd);
  if (!c)
    goto fail;

  c->data = data;
  c->cb = cb;
  c->who = 0;
  c->events = events;
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
  struct buffer *buf = (struct buffer *)data;

  events |= EPOLLET;

  if (fd == 0)
    warn("INVALID POLL FD PASSED");

  c = get_next_cb();
  if (!c)
    goto fail;

  if (buf) {
    memset(buf, 0, sizeof(struct buffer));
    buf->fd = -1;
  }

  c->fd = fd;
  c->events = events;
  c->data = data;
  c->cb = cb;
  c->last = now;
  c->who = 0;
  ev.events = events;
  ev.data.ptr = c;

  if (epoll_ctl(pollfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    goto fail;

  return 0;

fail:
  if (c)
    free_cb(c);
  return -1;
}

/* Sets up a 3 second timer to evict unresponsive connection */
/* NOTE: Not guaranteed to fire every 3 seconds! */
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
  nfile.rlim_cur = (MAX_CONCURRENCY*2)+200;
  nfile.rlim_max = (MAX_CONCURRENCY*2)+200;

  if (nfile.rlim_cur > nfile.rlim_max)
    errx(EX_SOFTWARE, "Cannot set max open file soft limit to %d"
                      " when hard limit is %d",
                       nfile.rlim_cur, nfile.rlim_max);

  if (setrlimit(RLIMIT_NOFILE, &nfile) < 0)
    warn("Cannot set open file limit");
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

  if (fcntl(fd, F_SETFL, O_NONBLOCK))
    err(EX_OSERR, "Cannot set server socket nonblock");

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EX_OSERR, "Cannot bind to address");

  if (listen(fd, 125) < 0)
    err(EX_OSERR, "Cannot listen on socket");

  freeaddrinfo(ai);
  return fd;
}

/* Shuts down and cleans up connections */
void disconnect(
    int fd)
{
  struct callback *c;
  if (fd == serverfd)
    return;

  assert(fd > 0);

  c = get_cb_by_fd(fd);
  epoll_ctl(poll, EPOLL_CTL_DEL, c->fd, NULL);

  free_cb(c);
  close(fd); 
}


/* Runs sendfile to send output file 
 * disconnect on finish */
int send_file(
    int fd,
    int events,
    void *data)
{
  struct buffer *buf = (struct buffer *)data;
  int sz;

  if ((events & EPOLLERR) == EPOLLERR)
    goto fail;

  do {
    sz = sendfile(fd, buf->fd, NULL, (buf->filesize - buf->offset));
    if (sz < 0)
      break;

    buf->offset += sz;
  } while (buf->offset < buf->filesize);

  if (sz < 0 && errno == EAGAIN) {
    if (resume_poll_fd(fd) < 0)
      goto fail;
    return 0;
  }

fail:
  return -1;
}

/* Sends the header contents, then preps to send file */
int send_header(
    int fd,
    int events,
    void *data)
{
  struct buffer *buf = (struct buffer *)data;
  int sz;

  if ((events & EPOLLERR) == EPOLLERR)
    goto fail;

  do {
    sz = send(fd, (buf->buf + buf->offset), (buf->sz - buf->offset), MSG_NOSIGNAL);
    if (sz < 0)
      break;

    buf->offset += sz;
  } while (buf->offset < buf->sz);

  if (sz < 0 && errno == EAGAIN) {
    if (resume_poll_fd(fd) < 0)
      return 0;
  }
  else if (sz < 0) {
    goto fail;
  }

  buf->offset=0;    
  buf->fd = open(SERV_FILE, O_RDONLY);
  if (buf->fd < 0)
    goto fail;

  if (mod_poll_fd(poll, fd, EPOLLOUT, send_file, buf) < 0)
    goto fail;

  return 0; 

fail:
  return -1;
}


/* Receives data from client */
int read_request(
    int fd,
    int events,
    void *data)
{
  int sz;
  char *p;
  struct buffer *buf = (struct buffer *) data;
  struct stat st;

  /* Read the buffer */
  do {
    sz = recv(fd, (buf->buf+buf->offset), (REQSZ-buf->offset), 0);
    if (sz <= 0) 
      continue;

    buf->offset += sz;
    if (buf->offset < 4)
      continue;
  
    p = (buf->buf + (buf->offset-4));
  } while (sz > 0);

  if (sz < 0 && errno != EAGAIN || sz == 0)
    goto fail;

  if (strncmp(p, "\r\n\r\n", 4) == 0) {

    if (stat(SERV_FILE, &st) < 0)
      goto fail;

    buf->sz = snprintf(buf->buf, REQSZ, 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n", 
        st.st_size);
    buf->filesize = st.st_size;

    if (mod_poll_fd(poll, fd, EPOLLOUT, send_header, buf) < 0)
      goto fail;
  }
  else {

    if (resume_poll_fd(fd) < 0)
      goto fail;
  }

  return 0;

fail:
  return -1;
}    


/* Accept a new connection */
int accept_conn(int fd, 
    int events, 
    void *data)
{
  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  struct buffer *buf = NULL;

  int eno;
  int cli;
  do {
    cli = accept4(fd, NULL, 0, SOCK_NONBLOCK);
    if (cli < 0)
      continue;
    if (cli == 0)
      warn("got 0 fd from accept?!");

    eno = errno;
  
    buf = malloc(sizeof(struct buffer));
    if (!buf)
     return -1;
  
    if (add_poll_fd(poll, cli, EPOLLIN, read_request, buf) < 0) {
      shutdown(cli, SHUT_RDWR);
    }

    errno = eno;
  } while (errno != EAGAIN);

  resume_poll_fd(fd);
  return 0;
}


/* Fires every 3 seconds, anything not dealt with after 3 seconds
 * gets disconnected as a timeout.
 * NOTE: No guarantees this will fire on time */
int read_timer(
    int fd,
    int events,
    void *data)
{
  unsigned long long u64;
  int i, tmpfd;
  int active=0;
  if ((events & EPOLLERR) == EPOLLERR)
    return -1;

  if (read(fd, &u64, sizeof(u64)) < 0)
    err(EX_OSERR, "Timer has failed");

  pthread_rwlock_wrlock(&rwlock);
  for (i=0; i < MAX_CONCURRENCY; i++) {

    if (callbacks[i] && callbacks[i]->fd == timer) continue;
    else if (callbacks[i] && callbacks[i]->fd == serverfd) continue;
    else if (callbacks[i] && (now - callbacks[i]->last) > TIMEOUT) {
      printf("Connection timed out: %d, %d\n", callbacks[i]->fd, now - callbacks[i]->last);
      shutdown(callbacks[i]->fd, SHUT_RDWR);
    }
    else if (callbacks[i] && callbacks[i]->fd) {
      active++;
    }

  }
  pthread_rwlock_unlock(&rwlock);

  if (resume_poll_fd(fd) < 0)
    err(EX_OSERR, "Couldn't rearm timer");
  
  printf("Active: %d\n", active);
  return 0;
}


/* The worker thread */
void * run_worker(
    void *data)
{
  queue_t q = data;
  pthread_t me = pthread_self();
  struct callback *cb;

  while (1) {
    cb = (struct callback *) queue_get(q);

    /* This is a sanity check which is attempting to ensure that
     * there is never two threads at once handling the same callback
     */
    //assert(cb->who == 0 || pthread_equal(cb->who, me));

    cb->last = now;
    cb->who = pthread_self();
    if (cb->cb) {
      /* Invoke the callback */
      /* Warning, passing the event 0 here is cheating */
      if (cb->cb(cb->fd, 0, cb->data) < 0)
        shutdown(cb->fd, SHUT_RDWR);
    }
    else
     shutdown(cb->fd, SHUT_RDWR);

  }
  return;
}



int main(void)
{
  memset(callbacks, 0, sizeof(*callbacks));
  if (pthread_rwlock_init(&rwlock, NULL))
    err(EX_OSERR, "Cannot initialize rwlock");

  signal(SIGPIPE, SIG_IGN);

  /* Setup the listening port */
  int workers = sysconf(_SC_NPROCESSORS_ONLN);
  int fd = tcp_server(SERVERPORT);
  int num, i;
  int savednum = 0;

  pthread_t *threads = calloc(sizeof(pthread_t), workers);
  serverfd = fd;
  struct epoll_event evs[MAX_CONCURRENCY];
  poll = setup_epoll();
  timer = setup_timer();

  if (!threads)
    err(EX_OSERR, "Cannot allocate memory for threads");

  /* Setup the queue */
  queue_t q = queue_init(0, workers);
  if (!q)
    err(EX_OSERR, "Cannot setup queue");

  /* Setup workers */
  for (i=0; i < workers; i++) {
    if (pthread_create(&threads[i], NULL, run_worker, (void *)q))
      err(EX_OSERR, "Cannot create thread");
  }

  /* Set the limits to match our max servicable requests */
  set_limits(MAX_CONCURRENCY);

  if (add_poll_fd(poll, fd, EPOLLIN, accept_conn, NULL) < 0)
    err(EX_OSERR, "Cannot add serverfd to set");

  if (add_poll_fd(poll, timer, EPOLLIN, read_timer, NULL) < 0)
    err(EX_OSERR, "Could not add timerfd to set");

  /* Go into event loop */
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

      if ((evs[i].events & EPOLLHUP) == EPOLLHUP) {
        disconnect(cb->fd);
        continue;
      }

      else if ((evs[i].events & EPOLLERR) == EPOLLERR) {
        disconnect(cb->fd);
        continue;
      }

      if (suspend_poll_fd(cb->fd) < 0) {
        disconnect(cb->fd);
        continue;
      }

      if (queue_put(q, cb) < 0)
        warn("Cannot put into queue!");

    }

    if (num > savednum) {
      savednum = num;
      printf("Concurrency: %d\n", savednum);
    }
    
  }

  exit(0);
}
