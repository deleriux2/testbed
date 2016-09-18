#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>

int main() {
  int fd;
  char *buf = malloc(128*1048576);
  if (!buf)
    err(EX_OSERR, "memerr");

  memset(buf, 'a', 128*1048576);
  while (1) {
    fd = open("./test/testfile.txt", O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (fd < 0)
      err(EX_OSERR, "Open");

    if (write(fd, buf, 128*1048576) < 0)
      err(EX_OSERR, "write");

    close(fd);
  }
}
