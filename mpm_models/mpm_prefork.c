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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sched.h>
#include <netdb.h>

#define SERV_FILE "/tmp/hello_world.html"
#define SERVERPORT "40001"
#define START_SERVERS 500
#define MIN_SERVERS 2000
#define MAX_SERVERS 4000
#define MIN_SPARE 2000
#define MAX_SPARE 3999
#define MAX_REQUESTS 10000

/* Vigilance is needed to atomically increment/decrement
 * some values, these macros take care of this
 */
#define up(a) \
  while (a == __sync_add_and_fetch(&a, 1)) \
    sched_yield();

#define down(a) \
  while (a == __sync_sub_and_fetch(&a, 1)) \
    sched_yield();


struct scoreboard {
  volatile int in_use;
  volatile int num_serv;
  struct {
    volatile pid_t pid;
    volatile int in_use;
  } state[MAX_SERVERS];
};

struct scoreboard *prefork;

/* Setup ulimits to ensure the number of connections 
 * we handle is supported
 */
static void set_limits(
    int limit)
{
  struct rlimit nfile, nproc;

  /* Get limits */
  if (getrlimit(RLIMIT_NPROC, &nproc) < 0)
    err(EX_OSERR, "Cannot retrieve number of processes limit");

  if (getrlimit(RLIMIT_NOFILE, &nfile) < 0)
    err(EX_OSERR, "Cannot retrive open file limit");

  /* Change limits */
  nproc.rlim_cur = MAX_SERVERS + 200;
  nfile.rlim_cur = MAX_SERVERS;

  if (nproc.rlim_cur > nproc.rlim_max)
    errx(EX_SOFTWARE, "Cannot set max process soft limit to %d"
                      " when hard limit is %d",
                       nproc.rlim_cur, nproc.rlim_max);

  if (nfile.rlim_cur > nfile.rlim_max)
    errx(EX_SOFTWARE, "Cannot set max open file soft limit to %d"
                      " when hard limit is %d",
                       nfile.rlim_cur, nfile.rlim_max);

  if (setrlimit(RLIMIT_NPROC, &nproc) < 0)
    err(EX_OSERR, "Cannot set number of processes limit");

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

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EX_OSERR, "Cannot bind to address");

  if (listen(fd, 125) < 0)
    err(EX_OSERR, "Cannot listen on socket");

  freeaddrinfo(ai);
  return fd;
}

static void cleanup_pid(
    pid_t p)
{
  int i;

  down(prefork->num_serv);
  //printf("Down: %d: %d\n", p, prefork->num_serv);
  for (i=0; i < MAX_SERVERS; i++) {
    if (prefork->state[i].pid == p) {
      /* Clears the state entry */
      prefork->state[i].pid = 0;
      prefork->state[i].in_use = 0;
    }
  }
}

static void start_child(
    int fd,
    int entry)
{
  char buf[8192];
  int i, yes=1, sz=0, rc;
  int cli=-1, file=-1;
  struct stat st;
  struct timeval tm = {3,0};
  pid_t pid;
  pid = fork();

  memset(buf, 0, 8192);

  if (pid < 0)
    err(EX_OSERR, "Cannot create child process");
  else if (pid) {
    up(prefork->num_serv);
    //printf("up: %d\n", prefork->num_serv);
    /* Parent goes back */
    return;
  }

  /* Child handler code is here! */
  prefork->state[entry].pid = getpid();
  prefork->state[entry].in_use = 0;

  /* Handle requests */
  for (i=0; i < MAX_REQUESTS; i++) {
    cli = accept4(fd, NULL, 0, SOCK_CLOEXEC);
    if (cli < 0) {
      warn("Cannot accept a connection");
      continue;
    }
    prefork->state[entry].in_use = 1;
    up(prefork->in_use);

    /* CORK the socket for better efficiency */
    if (setsockopt(cli, IPPROTO_TCP, TCP_CORK, &yes, sizeof(yes)) < 0) {
      warn("Cannot cork socket");
      goto fin;
    }

    if (setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tm, sizeof(tm)) < 0) {
      warn("Socket timed out");
      goto fin;
    }

    if (setsockopt(cli, SOL_SOCKET, SO_SNDTIMEO, &tm, sizeof(tm)) < 0) {
      warn("Socket timed out");
      goto fin;
    }

    /* Read the client request, super lazy mode,
     * we just accept ANY request as a http request
     */
    rc = recv(cli, buf, 8192, 0);
    if (rc == 0) {
      //warnx("Client disconnected");
      goto fin; 
    }
    else if (rc < 0) {
      warn("Cannot read from client");
    }

    usleep(40000);

    /* Super lazy mode, open the file that contains our content and serve it up */
    file = open(SERV_FILE, O_RDONLY);
    if (file < 0) {
      warn("Cannot open file");
      goto fin;
    }

    /* Get the size of the file */
    if (stat(SERV_FILE, &st) < 0) {
      warn("Cannot get file size");
      goto fin;
    }

    /* Construct the first portion of our packet */
    sz = snprintf(buf, 8192, "HTTP 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"
                             "Connection: close\r\n", st.st_size);
    rc = send(cli, buf, sz, MSG_NOSIGNAL);
    if (rc < 0) {
      warn("Cannot send header");
      goto fin;
    }

    /* Pass the content of the file */
    if (sendfile(cli, file, 0, st.st_size) < 0) {
      warn("Sendfile failed");
      goto fin;
    }

    /* Uncork */
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) < 0) {
      warn("Cannot uncork socket");
      goto fin;
    }

  fin:
    if (cli > -1)
      shutdown(cli, SHUT_RDWR);
    if (file > -1)
      close(file);

    sz = 0;
    file = -1;
    cli = -1;
    memset(&st, 0, sizeof(st));
    memset(buf, 0, 8192);
    prefork->state[entry].in_use = 0;
    down(prefork->in_use);
  }

  cleanup_pid(getpid());
  exit(0);
}



int main(void)
{
 int i, j;
 pid_t p;
 int ns, st;
 int slots_to_fill;

 /* Initialize the scoreboard */
 prefork = (struct scoreboard *) mmap(
            NULL, 
            sizeof(*prefork), 
            PROT_READ | PROT_WRITE,
            MAP_SHARED|MAP_ANONYMOUS,
            -1,
            0);

 if (prefork == MAP_FAILED)
   err(EX_OSERR, "Cannot assign scoreboard");

  prefork->num_serv = 0;
  prefork->in_use = 0;
  memset(prefork, 0, sizeof(prefork));

  /* Setup the listening port */
  int fd = tcp_server(SERVERPORT);

  /* Set the limits to match our max servicable requests */
  set_limits(MAX_SERVERS);

  for (i=0; i < START_SERVERS; i++) {
    start_child(fd, i);
  }

  /* Parent prefork handling code */
  while (1) {
  next:
    ns = 0;

    if ((p = waitpid(0, &st, WNOHANG)) < 0) {
      if (errno == ECHILD) {
        exit(0);
      }
    }
    else if (p) {
      cleanup_pid(p);
      ns = 1;
    }

    /* If the number of inuse servers is greater than MAX_SPARE 
     * kill a spare server.
     */
    if ((prefork->num_serv - prefork->in_use) > MAX_SPARE &&
         prefork->num_serv > MIN_SERVERS) {
      /* Find a spare pid and kill it */
      for (i=0; i < MAX_SERVERS; i++) {
        if (prefork->state[i].pid && !prefork->state[i].in_use) {

          /* Its ok if the kill doesn't work */
          kill(prefork->state[i].pid, SIGTERM);
          ns =1;
          break;
        }
      }
    }

    /* If the number of servers is lower than MIN_SERVERS, spawn 
     * more servers to make up the number */
    if (prefork->num_serv < MIN_SERVERS) {
      ns = 1;
      slots_to_fill = MIN_SERVERS - prefork->num_serv;
      for (j = slots_to_fill; j > 0; j--) {
        for (i=0; i < MAX_SERVERS; i++) {
          if (prefork->state[i].pid == 0) {
            start_child(fd, i);
            break;
          }
        }
      }
    }

    /* If the number of idle servers is less than MIN_SPARE
     * spawn a up to MAX_SPARE new children
     */

    if ((prefork->num_serv - prefork->in_use) < MIN_SPARE &&
                             prefork->num_serv < MAX_SERVERS) {

      slots_to_fill = MAX_SPARE - (prefork->num_serv - prefork->in_use);
      if ((prefork->num_serv + slots_to_fill) > MAX_SERVERS)
        slots_to_fill = MAX_SERVERS - prefork->num_serv;

      /* Find a spare slot */
      for (j = slots_to_fill; j > 0; j--) {
        for (i=0; i < MAX_SERVERS; i++) {
          if (prefork->state[i].pid == 0) {
            start_child(fd, i);
            break;
          }
        }
      }
      ns = 1;
    }

    if (!ns)
      sleep(1);
  }
  
  exit(0);
}
