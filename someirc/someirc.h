#ifndef _COMMON_H_
#define _COMMON_H_
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <fcntl.h>

#include <netdb.h>
#include <sysexits.h>
#include <err.h>
#include <assert.h>

#define MAXNICK 16
#define MSGMAX 512

struct sendbuf {
  char msg[MSGMAX];
  int len;
  int index;
  TAILQ_ENTRY(sendbuf) tq;
};

typedef struct client {
  int fd;
  char peername[64];
  
  TAILQ_HEAD(sendbufhead, sendbuf) sbh;

  struct {
    char msg[MSGMAX];
    int index;
  } msgbuf;
} client_t;

int client_sendrecv(int fd, int event, void *data);
void client_destroy(void *data);

#endif
