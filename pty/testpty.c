#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pty.h>


int main() {

  int a, b;
  char name[64];
//       int openpty(int *amaster, int *aslave, char *name,
//                   const struct termios *termp,
//                   const struct winsize *winp);
  openpty(&a, &b, name, NULL, NULL);
  exit(0);
}
