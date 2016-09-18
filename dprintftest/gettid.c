#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
  printf("%d\n", SYS_gettid);
}
