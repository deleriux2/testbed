#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

int main() {
  int i;
  char c=65;
  pid_t pid;
  signal(SIGCHLD, SIG_IGN);

  /* Allocate some memory */
  char *hog = malloc(104857600);
  memset(hog, c, 104857600);

  for (i=1; i < 4; i++) {
    if (fork())
      continue;
    memset(hog, c+i, 104857600);
    break;
  }
  sleep(3);
  printf("Pid %d shows HOG[1048576] saying %c\n", getpid(), hog[1048576]);
  pause();
}
