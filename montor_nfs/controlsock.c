#include "common.h"
#include "event.h"

#include <sys/uio.h>
#include <sys/un.h>
#include <sys/timerfd.h>

#define MAX_CONNECTIONS 2
#define CONTROLSOCK_PATH "/var/run/audisp_path_monitor.sock"
#define MAX_BUFFER 65536

extern struct watched_paths wpaths;
int numconnected = 0;
int timer = -1;
int client = -1;
extern int running;

uint32_t timeout;
uint32_t buflen;
uint32_t offset;
char buffer[MAX_BUFFER];


static int stop_audit(
    void)
{
  int fd = audit_open();
  if (fd < 0)
    goto fail;

  if (audit_teardown_syscalls(fd) < 0)
    goto fail;

  audit_close(fd);
  close(timer);
  timer = -1;
  running = 0;
  syslog(LOG_NOTICE, "Audit rules needed by "PROGNAME" have been removed");
  return 0;

fail:
  syslog(LOG_CRIT, "Unable to flush audit rules: %s. You must delete the rule in auditctl", strerror(errno));
  audit_close(fd);
  return -1;
}


static int timer_expired(
    int fd,
    int event,
    void *data)
{
  uint64_t fired;
  int rc;
  char sbuf[MAX_BUFFER];
  char *p;
  struct path_counts *pc;

  syslog(LOG_INFO, "Timer is finished");
  /* Read from the FD */
  rc = read(fd, &fired, sizeof(fired));
  /* Dont care what the result of this is just that it fires in a timely manner */

  if (stop_audit() < 0)
    syslog(LOG_CRIT, "Unable to remove rules from audit. Rules must be removed manually");

  memset(sbuf, 0, sizeof(sbuf));
  p = sbuf;

  for (pc=wpaths.lh_first; pc != NULL; pc=pc->entries.le_next) {
    p += snprintf(p, 4096, "%s: Reads: %d Writes %d\n", pc->path, pc->reads, pc->writes);
  }
  if (send(client, sbuf, sizeof(sbuf), MSG_NOSIGNAL) < 0) 
    syslog(LOG_ERR, "Tried to send a report but failed: %s", strerror(errno));
  else
    syslog(LOG_INFO, "Sent report");

  shutdown(client, SHUT_RDWR);
  close(client);
  numconnected--;
  
  return 0;
}


static int start_audit(
    int fd,
    int timeout)
{
  int auditfd;
  struct path_counts *pc;
  struct itimerspec fdtimeout = { {0, 0}, {timeout, 0} };

  /* Setup timer and add to event system */
  timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  if (timer < 0) {
    syslog(LOG_ERR, "Could not create timerfd: %s", strerror(errno));
    return -1;
  }

  if (timerfd_settime(timer, 0, &fdtimeout, NULL) < 0) {
    syslog(LOG_ERR, "Could not set timeout on timer: %s", strerror(errno));
    return -1;
  }

  if (event_add_fd(timer, timer_expired, NULL, NULL, EPOLLIN) < 0) {
    syslog(LOG_ERR, "Could not add timerfd to event manager: %s", strerror(errno));
    goto fail;
  }

  /* Begin the audit */
  if ((auditfd = audit_open()) < 0) {
    syslog(LOG_ERR, "Unable to open audit socket: %s", strerror(errno));
    goto fail;
  }

  for (pc = wpaths.lh_first; pc != NULL; pc=pc->entries.le_next) {
    if (audit_setup_syscalls(auditfd, pc->path) < 0) {
      syslog(LOG_ERR, "Unable to setup syscall paths to listen on: %s", strerror(errno));
      goto fail;
    }
  }
  running = 1;

  syslog(LOG_NOTICE, "Armed timer to expire in %d seconds", timeout);
  audit_close(auditfd);
  return 0;
fail:
  audit_close(auditfd);
  close(timer);
  return -1;  
}


static int read_client(
    int fd,
    int event,
    void *data)
{
  struct iovec vec[3];
  char *p;
  int rc;
  struct path_counts *pc;

  if (event & (EPOLLHUP|EPOLLERR)) {
    syslog(LOG_ERR, "Connection error to client. Stopping rule auditing.");
    stop_audit();
    shutdown(fd, SHUT_RDWR);
    close(fd);
    numconnected--;
    return 0;
  }

  if (!(event & EPOLLIN)) {
    syslog(LOG_ERR, "Connection error to client. Stopping rule auditing.");
    stop_audit();
    shutdown(fd, SHUT_RDWR);
    close(fd);
    numconnected--;
    return 0;
  }

  vec[0].iov_base = &timeout;
  vec[0].iov_len = sizeof(timeout);
  vec[1].iov_base = &buflen;
  vec[1].iov_len = sizeof(buflen);
  vec[2].iov_base = buffer;
  vec[2].iov_len = sizeof(buffer);

  rc = readv(fd, vec, 3);
  if (rc <= 0) {
    syslog(LOG_ERR, "Connection error to client. Stopping rule auditing.");
    stop_audit();
    shutdown(fd, SHUT_RDWR);
    close(fd);
    numconnected--;
    return 0;
  }

  if (timeout > 1800 || timeout <= 0) {
    send(fd, "This system accepts a timeout between 1 and 1800 seconds\n", 61, MSG_NOSIGNAL);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    numconnected--;
    return 0;
  }
  if (buflen > MAX_BUFFER) {
    syslog(LOG_NOTICE, "Client sent a malformed packet. Aborted connection");
    send(fd, "Malformed packet detected. Goodbye\n", 35, MSG_NOSIGNAL);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    numconnected--;
    return 0;
  }

  /* Now parse the buffer */
  p = buffer;
  while (p[0] != 0 && p - buffer < MAX_BUFFER) {
    if (p[0] != '/') {
      syslog(LOG_NOTICE, "Client sent a malformed packet. Aborted connection");
      send(fd, "All paths must be absolute\n", 26, MSG_NOSIGNAL);
      shutdown(fd, SHUT_RDWR);
      close(fd);
      numconnected--;
      return 0;
    }
    pc = malloc(sizeof(*pc));
    if (!pc)
      goto fail;

    /* Insert the path to wpaths */
    strncpy(pc->path, p, PATH_MAX);
    pc->reads = 0;
    pc->writes = 0;
    LIST_INSERT_HEAD(&wpaths, pc, entries);
    p += strlen(p)+1;
   syslog(LOG_INFO, "Requested monitoring of path %s", pc->path);
  }

  syslog(LOG_NOTICE, "Received request: Timeout=%d", timeout);
  start_audit(fd, timeout);
  return 0;

fail:
  while (wpaths.lh_first != NULL) {
    pc = wpaths.lh_first;
    LIST_REMOVE(wpaths.lh_first, entries);
    free(pc);
  }
  stop_audit();
  return 0;
}




static int accept_connection(
    int fd,
    int event,
    void *data)
{
  int child;
  struct path_counts *pc;

  if (event & (EPOLLHUP|EPOLLERR)) {
    syslog(LOG_ERR, "Received a error event from control socket handler. Aborting");
    exit(1);
  }

  if (!(event & EPOLLIN)) {
    syslog(LOG_WARNING, "Got an unexpected signal from control socket handler. Ignoring");
    return 0;
  }

  if ((child = accept4(fd, NULL, NULL, SOCK_CLOEXEC)) < 0) {
    syslog(LOG_WARNING, "Got an accept request that failed. Ignoring.");
    return 0;
  }

  if (numconnected+1 >= MAX_CONNECTIONS) {
    printf("Reach max conns\n");
    send(child, "There can only be one connected client at a time", 48, MSG_NOSIGNAL);
    shutdown(child, SHUT_RDWR);
    close(child);
    return 0;
  }

  if (event_add_fd(child, read_client, NULL, NULL, EPOLLIN) < 0) {
    syslog(LOG_WARNING, "Unable to accept connection from new client: %s", strerror(errno));
    return 0;
  }
  timeout = 0;
  buflen = 0;
  memset(buffer, 0, sizeof(buffer));

  /* Clear out the old records, if any exists */
  while (wpaths.lh_first != NULL) {
    pc = wpaths.lh_first;
    LIST_REMOVE(wpaths.lh_first, entries);
    free(pc);
  }
  LIST_INIT(&wpaths);

  syslog(LOG_INFO, "Accepted connection from client");
  numconnected++;
  client = child;
  return 0;
}

void controlsock_init(
    void)
{
  struct sockaddr_un addr;
  int fd = -1;
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    syslog(LOG_ERR, "Cannot create control socket: %s", strerror(errno));
    exit(1);
  }

  unlink(CONTROLSOCK_PATH);

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, CONTROLSOCK_PATH);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "Could not bind control socket to path: %s", strerror(errno));
    exit(1);
  }

  if (fcntl(fd, F_SETFD, O_CLOEXEC) < 0) {
    syslog(LOG_ERR, "Could not set cloexec on contro socket: %s", strerror(errno));
    exit(1);
  }

  if (chmod(CONTROLSOCK_PATH, S_IRUSR|S_IWUSR) < 0) {
    syslog(LOG_ERR, "Could not set mode on control socket path: %s", strerror(errno));
    exit(1);
  }

  if (listen(fd, 2) < 0) {
    syslog(LOG_ERR, "Could not listen on socket: %s", strerror(errno));
    exit(1);
  }

  if (event_add_fd(fd, accept_connection, NULL, NULL, EPOLLIN) < 0) {
    syslog(LOG_ERR, "Could not add control socket to event manager: %s", strerror(errno));
    exit(1);
  }

  syslog(LOG_NOTICE, "Established control socket on %s", CONTROLSOCK_PATH);
  return;
}
