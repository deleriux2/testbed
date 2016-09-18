#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  printf("Me: %d, Effective Me: %d\n", getuid(), geteuid());
  //if (setuid(0) < 0) {
//    perror("setuid");
//    return 1;
//  }
  return 0;
}
