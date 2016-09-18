#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

int main(int argc, const char **argv) {
  printf("%p\n", argv[1]);
  int i;
  for (i=0; i < argc; i++) {
    printf("arg: %s\n", argv[i]);
  }
  pause();
}
