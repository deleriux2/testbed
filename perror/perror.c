#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(const int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Pass an errno argument");
    exit(1);
  }

  errno = atoi(argv[1]);
  perror("");
  exit(0);
}
