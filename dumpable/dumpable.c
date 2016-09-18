#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>

int main() {
  int on = 0;
  while (1) {
    if (prctl(PR_SET_DUMPABLE, (on & 1), 0, 0, 0, 0) < 0) {
      perror("");
      exit(0);
    }
    on++;
    sleep(3);
  }

  pause();
}

