#include "common.h"
#include "event.h"
#include <sys/signalfd.h>
#include <sys/uio.h>
#include <signal.h>
#include <cap-ng.h>

static volatile int do_shutdown = 0;

struct watched_paths wpaths;
int running = 0;

static void flush_audit(
    void)
{
  int fd;
  syslog(LOG_INFO, "Flushing any previous audit rules");
  if ((fd = audit_open()) < 0) {
    syslog(LOG_ERR, "Could not open audit fd: %s", strerror(errno));
    exit(1);
  }

  if (audit_request_status(fd) < 0) {
    syslog(LOG_ERR, "Cannot use audit: %s", strerror(errno));
    exit(1);
  }
    

  if (audit_teardown_syscalls(fd) < 0) {
    syslog(LOG_ERR, "Unable to flush old audit rules: %s", strerror(errno));
    exit(1);
  }

  audit_close(fd);
}



static int signal_read(
  int fd,
  int event,
  void *data)
{
  struct signalfd_siginfo siginfo;
  int rc;

  if (event & (EPOLLHUP|EPOLLERR)) {
    syslog(LOG_ERR, "Received a error event from signal read event handler. Aborting");
    exit(1);
  }

  if (!(event & EPOLLIN)) {
    syslog(LOG_WARNING, "Got an unexpected signal from signal read event handler. Ignoring");
    return 0;
  }

  rc = read(fd, &siginfo, sizeof(siginfo));
  if (rc < 0) {
    syslog(LOG_ERR, "Unable to read from signal handler: %s. Probably a bug", strerror(errno));
    return 0;
  }

  if (rc < sizeof(siginfo)) {
    syslog(LOG_ERR, "Siginfo read returned less than expected bytes. Aborting");
    exit(1);
  }

  switch (siginfo.ssi_signo) {
    case SIGTERM:
      flush_audit();
      syslog(LOG_NOTICE, "Given notice to exit. Shutting down");
      do_shutdown = 1;
    break;

    case SIGHUP:
      syslog(LOG_NOTICE, "HUPing this program currently has no effect. But may do in the future");
    break;
  }
}



int audit_read(
    int fd,
    int event,
    void *data)
{
  int rc;
  auparse_state_t *parser = (auparse_state_t *)data;
  char buf[MAX_AUDIT_MESSAGE_LENGTH];

  memset(buf, 0, sizeof(buf));
  if (event & (EPOLLHUP|EPOLLERR)) {
    syslog(LOG_ERR, "Received a error event from signal audit event handler. Aborting");
    struct path_counts *pc;
    /* Test test test */
    for (pc=wpaths.lh_first; pc != NULL; pc=pc->entries.le_next) {
      printf("Path: %s, Reads: %d, Writes: %d\n", pc->path, pc->reads, pc->writes); 
    }
    exit(1);
  }

  if (!(event & EPOLLIN)) {
    syslog(LOG_WARNING, "Got an unexpected signal from audit read event handler. Ignoring");
    return 0;
  }

  /* Read in from the fd and pass to the parser */
  rc = read(fd, buf, MAX_AUDIT_MESSAGE_LENGTH);
  if (rc < 0) {
    syslog(LOG_ERR, "Cannot read from audit descriptor: %s", strerror(errno));
    return -1;
  }

 /* Pass to parser */
 if (running) {
   if (auparse_feed(parser, buf, rc) < 0) {
     syslog(LOG_ERR, "Parser returned invalid state");
     return -1;
   }
  }

  return 0;
}



static int setup_signals(
    void)
{
  /* Block these signals, they are managed by the fd */
  int fd = -1;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGTERM);

  if (sigprocmask(SIG_SETMASK, &set, NULL) < 0) {
    syslog(LOG_ERR, "Could not setup signal blocking: %s", strerror(errno));
    exit(1);
  }

  if ((fd = signalfd(-1, &set, SFD_CLOEXEC) )< 0) {
    syslog(LOG_ERR, "Could not spawn a signal fd: %s", strerror(errno));
    exit(1);
  }

  return fd;
}




int main(
  const int argc,
  const char **argv)
{

  int auditfd = -1;
  int signalfd = -1;
  auparse_state_t *parser = NULL;

  LIST_INIT(&wpaths);

  /* Open the syslog */
  openlog(PROGNAME, LOG_PID, LOG_DAEMON);
  syslog(LOG_NOTICE, "Dispatcher starting");

  if (chdir("/") < 0) {
    syslog(LOG_ERR, "Unable to change directory to '/': %s", strerror(errno));
    exit(1);
  }

  signalfd = setup_signals();

  /* Close the old fd and replace with a known one */
  auditfd = dup(0);
  close(0);

  /* Drop capabilities */
  capng_clear(CAPNG_SELECT_BOTH);
  capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE|CAPNG_BOUNDING_SET, CAP_AUDIT_CONTROL);
  capng_apply(CAPNG_SELECT_BOTH);

  /* Creating event handler */
  event_init();

  /* Initialize the parser */
  parser = parser_init(&wpaths);
  auparse_add_callback(parser, parser_parse_event, &wpaths, NULL);

  /* On initial startup, we destroy any audit events we own */
  flush_audit();

  /* Setup the control socket */
  controlsock_init();

  /* Add our event handles to the event subsystem */
  if (event_add_fd(signalfd, signal_read, NULL, NULL, EPOLLIN) < 0) {
    syslog(LOG_ERR, "Could not add signal to event handler: %s", strerror(errno));
    exit(1);
  }
  if (event_add_fd(auditfd, audit_read, NULL,  parser, EPOLLIN) < 0) {
    syslog(LOG_ERR, "Could not add auditfd to event handler: %s", strerror(errno));
    exit(1);
  }


  syslog(LOG_NOTICE, "Entering event loop");
  while (1) {
    event_loop(1, -1);
  }

  exit(0);
}
