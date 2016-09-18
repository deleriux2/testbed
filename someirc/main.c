#include "someirc.h"
#include "event.h"
#include "message.h"

char servername[64];
int serverfd;

static int servername_init(
    void)
{
  memset(servername, 0, 64);
  if (gethostname(servername, 63) < 0)
    err(EX_SOFTWARE, "Cannot get hostname");
}

static int tcp_server(
    const char *hostname,
    const char *servname)
{
  int rc;
  int fd = -1;

  struct addrinfo *ai, hints;
  memset(&hints, 0, sizeof(hints));
  ai = NULL;

  assert(hostname);
  assert(servname);

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE;

  if ((rc = getaddrinfo(hostname, servname, &hints, &ai))) {
    errx(EX_NOHOST, "Cannot resolve address: %s\n", gai_strerror(rc));
    goto fail;
  }

  fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
  if (fd < 0) {
    err(EX_OSERR, "Cannot allocate socket");
    goto fail;
  }

  rc = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc)) < 0) {
    err(EX_OSERR, "Cannot set socket option");
    goto fail;
  }

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
    err(EX_OSERR, "Cannot bind to address");
    goto fail;
  }

  if (listen(fd, 10) < 0) {
    err(EX_OSERR, "Cannot perform listen");
    goto fail;
  }

  freeaddrinfo(ai);
  return fd;
  
fail:
  freeaddrinfo(ai);
  return -1;
}

static int accept_connection(
    int serverfd,
    int event,
    void *data)
{
  int rc;
  client_t *cli;
  struct sockaddr addr;
  socklen_t addrlen = sizeof(addr);
  //struct message msg; // TEMPORARY

  assert(serverfd > -1);

  cli = malloc(sizeof(*cli));
  if (!cli) {
    warn("Cannot allocate memory to accept connection");
    goto fail;
  }

  TAILQ_INIT(&cli->sbh);

  memset(cli, 0, sizeof(cli));
  cli->fd = -1;

  /* Accept connection */
  cli->fd = accept4(serverfd, &addr, &addrlen, SOCK_NONBLOCK);
  if (cli->fd < 0) {
    warn("Cannot accept a connection");
    goto fail;
  }

  /* Resolve the peername */
  rc = getnameinfo(&addr, addrlen, cli->peername, 
                               63, NULL, 0, NI_NAMEREQD);
  if (rc) {
    switch (rc) {
      /* If the hostname is too big, store the address */
      case (EAI_OVERFLOW):
        if (inet_ntop(addr.sa_family, &addr, cli->peername, 63)) {
          warn("Cannot resolve client hostname");
          break;
        }
        else {
          goto ok;
        }
      break;

      case EAI_SYSTEM:
        warn("Cannot resolve client hostname");
      break;

      default:
        warnx("Cannot resolve client hostname: %s", gai_strerror(rc));
      break;
    }
    goto fail;
  }

ok:
  memset(&cli->msgbuf, 0, sizeof(cli->msgbuf));

  /* Add to our event list */
  if (event_add_fd(cli->fd, client_sendrecv, client_destroy, cli, EPOLLIN) < 0) {
    warn("Cannot add FD to event list");
    goto fail;
  }

/* ** TEMPORARY  **
  memset(&msg, 0, sizeof(msg));
  msg.paramno = 2;
  strcpy(msg.prefix, servername);
  strcpy(msg.command, "NOTICE");
  strcpy(msg.params[0], "*");
  strcpy(msg.params[1], "Hello world");
  message_push(cli, &msg);

  strcpy(msg.params[1], "This is a test");
  message_push(cli, &msg);

  strcpy(msg.params[1], "This is a second test");
  message_push(cli, &msg);
*/

  return 0;
fail:
  client_destroy(cli);
}


int main(const int argc, char **argv) {
  message_init();
  servername_init();
  event_init();
  serverfd = tcp_server("localhost", "52134");

  if (event_add_fd(serverfd, accept_connection, NULL, NULL, EPOLLIN) < 0)
    exit(EX_OSERR);

  while (event_loop(10, -1) > -1);

}
