#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <limits.h>
#include <sysexits.h>
#include <stdio.h>

#define MAXPIDS 170
#define NUMFILES 40
#define READSZ 16384
#define BASEDIR "./randomandlockdir"
#define BASENAME "lockrand"

void lock_and_read_rand()
{
  int fd;
  char path[PATH_MAX];
  char buf[READSZ];
  struct flock lck = { F_WRLCK,  SEEK_SET, 16777215,1, 0 };

  snprintf(path, PATH_MAX, "%s/%s.%d", BASEDIR, BASENAME, rand() % NUMFILES);

  if ((fd = open(path, O_RDWR)) < 0)
    err(EX_OSERR, "Cannot open file");
 
  if (fcntl(fd, F_SETLKW, &lck) < 0)
    err(EX_OSERR, "Cannot lock file");

  /* Read first 16k bytes */
  if (read(fd, buf, READSZ) < 0)
    err(EX_OSERR, "Cannot read file");

  lck.l_type = F_UNLCK;
  if (fcntl(fd, F_SETLKW, &lck) < 0)
    err(EX_OSERR, "Cannot unlock file");
  close(fd);
}
fd
int main()
{
  int i, st;
  pid_t pid;
  /* Constant seed */
  srand(1);
  for (i=0; i < MAXPIDS; i++) {
    pid = fork();
    if (pid) {
      continue;
    }
    else {
      while (1)
        lock_and_read_rand();
      exit(0);
    }
  }

  for (i=0; i < MAXPIDS; i++) {
    wait(&st);
  }

  exit(0);
}
