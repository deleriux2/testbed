#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEMSZ1 5368709120

int main() {
  char *mem = malloc(MEMSZ1);
  if (mem)
    memset(mem, 'a', MEMSZ1);
  pause();
}
