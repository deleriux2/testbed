#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

int main()
{
  mqd_t mq;
  struct mq_attr a = { 0, 5, 1500, 0 };
  mq = mq_open("/myq", O_CREAT|O_RDWR, S_IRUSR|S_IWUSR, &a);
  char buf[3000];
  int sz;
  memset(buf, 0, 3000);

  if (mq < 0)
    err(EX_OSERR, "Cannot open message queue");

 if (mq_send(mq, "hello world", 11, 0) < 0)
    err(EX_OSERR, "Cannot send to message queue");

 if ((sz = mq_receive(mq, buf, 3000, NULL)) < 0)
    err(EX_OSERR, "Cannot receive from message queue");

  printf("In the queue %d bytes: %s\n", sz, buf);

  exit(0);
}
