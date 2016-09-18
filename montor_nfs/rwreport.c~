#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <err.h>
#include <sysexits.h>

#define CONTROLSOCK_PATH "/var/run/audisp_path_monitor.sock"
#define MAX_BUFFER 65536

int main(
    const int argc,
    const char **argv)
{
  struct sockaddr_un addr = { AF_UNIX, CONTROLSOCK_PATH };
  struct iovec vec[3];
  int timeout;
  int buflen;
  int fd = -1;
  int i;
  int rc;
  char buffer[MAX_BUFFER];
  char *p;
  memset(buffer, 0, sizeof(buffer));

  /* Check we have at least a timeout and single path */
  if (argc < 3)
    err(EX_SOFTWARE, "You must supply a timeout and at least one path to monitor");

  timeout = atoi(argv[1]);
  if (timeout <= 0)
    err(EX_SOFTWARE, "An invalid timeout was specified");

  p = buffer;
  for (i=2; i < argc; i++) {
    strncpy(p, argv[i], MAX_BUFFER-(p-buffer));
    p += strlen(p)+1;
  }
  buflen = p-buffer;

  /* Connect to unix socket */
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    err(EX_OSERR, "Could not create socket");

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    err(EX_OSERR, "Could not connect to socket");

  /* Once connected, send out request */
  vec[0].iov_base = &timeout;
  vec[0].iov_len = sizeof(timeout);
  vec[1].iov_base = &buflen;
  vec[1].iov_len = sizeof(buflen);
  vec[2].iov_base = buffer;
  vec[2].iov_len = buflen;

  rc = writev(fd, vec, 3);
  if (rc < 0)
    err(EX_OSERR, "Could not write to socket");

  /* Re-use buffer to receive result */
  memset(buffer, 0, sizeof(buffer));
  if (read(fd, buffer, MAX_BUFFER) < 0)
    err(EX_OSERR, "Could not read from socket");

  printf("Report results:\n\n%s", buffer);
}
