#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  printf("%d: %d\n", getuid(), geteuid());
  seteuid(1000);
  printf("%d: %d\n", getuid(), geteuid());
  seteuid(23);
  printf("%d: %d\n", getuid(), geteuid());
  if (access("./file.txt", R_OK))
    perror("Access");
  exit(0);
}
