#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <err.h>
#include <sysexits.h>
#include <errno.h>

#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#define THREADS 3
#define NUMCHILD 3
#define DEF_OPEN_LIMIT 256

/* The gimmick in this program is to constantly dup an FD
 * until we run out of file handles */

void dup_fds(
  int basefd)
{
  int i;
  int *fds = calloc(1048576, sizeof(int));
  char etxt[256];
  int me = pthread_self();

  for (i=0; i < 1048576; i++)
    fds[i] = -1;

  for (i=0; i < 1048576; i++) {
    fds[i] = dup(basefd);
    if (fds[i] < 0) {
      strerror_r(errno, etxt, 256);
      fprintf(stderr, "Cannot dup file: %s\n", etxt);
      return;
    }
    usleep(100000 + (rand_r(&me) % 400000));
  }
}

void * run_thread(
  void *data)
{
  /* This procedure should not be independent */
  struct rlimit ofiles;
  int i;
  i = pthread_self();

  /* Obtain the open files limit */
  if (getrlimit(RLIMIT_NOFILE, &ofiles) < 0) {
    perror("cannot get limits");
    pthread_exit(NULL);
  }

  /* Assign a random value to current limit */
  i = getpid();
  ofiles.rlim_cur = 128 + (rand_r(&i) % 896);

  /* Set the limit */
  if (setrlimit(RLIMIT_NOFILE, &ofiles) < 0) {
    perror("cannot set limits");
    pthread_exit(NULL);
  }


  dup_fds(1);
}


void run_child(
  void)
{
  int i;
  struct rlimit ofiles;
  pthread_t threads[THREADS];

  /* Obtain the open files limit */
  if (getrlimit(RLIMIT_NOFILE, &ofiles) < 0)
    err(EX_OSERR, "Cannot obtain limits");

  /* Assign a random value to current limit */
  i = getpid();
  ofiles.rlim_cur = 128 + (rand_r(&i) % 896);

  /* Set the limit */
  if (setrlimit(RLIMIT_NOFILE, &ofiles) < 0)
    err(EX_OSERR, "Canot set limits");

  /* Create threads */
  for (i=0; i < THREADS; i++) {
    if (pthread_create(&threads[i], NULL, run_thread, NULL))
      err(EX_OSERR, "Cannot spawn thread");
  }

  dup_fds(1);

  for (i=0; i < THREADS; i++)
    if (pthread_join(threads[i], NULL))
      err(EX_OSERR, "Cannot join thread");

  exit(0);
}


int main()
{
  int i, s;
  /* Spawn children */
  for (i=0; i < NUMCHILD; i++) {
    if (fork()) {
      continue;
    }
    run_child();
  }

  for (i=0; i < NUMCHILD; i++) {
    if (wait(&s) < 0)
      warn("wait failed");
  }

  return 0;
}
