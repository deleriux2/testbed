#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <err.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>

struct {
  int numfds;
  int numevents;
  struct epoll_event *events;
} connections = { 0, 0, NULL };

static int create_srv_socket(const char *port) {
  int fd = -1;
  int rc;
  struct addrinfo *ai = NULL, hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;

  if ((rc = getaddrinfo(NULL, port, &hints, &ai)) != 0)
    errx(EX_UNAVAILABLE, "Cannot create socket: %s", gai_strerror(rc));

  if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
    err(EX_OSERR, "Cannot create socket");

  rc = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc)) < 0)
    err(EX_OSERR, "Cannot setup socket options");

  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    err(EX_OSERR, "Cannot bind to socket");

  if (listen(fd, 25) < 0)
    err(EX_OSERR, "Cannot setup listen length on socket");

  return fd;
}

static int create_epoll(void) {
  int fd;
  if ((fd = epoll_create1(0)) < 0)
    err(EX_OSERR, "Cannot create epoll");
  return fd;
}

static bool epoll_join(int epollfd, int fd, int events) { 
  struct epoll_event ev;
  ev.events = events;
  ev.data.fd = fd;

  if ((connections.numfds+1) >= connections.numevents) {
    printf("Adding more memory for connections\n");
    connections.numevents+=1024;
    connections.events = realloc(connections.events, 
      sizeof(connections.events)*connections.numevents);
    if (!connections.events)
      err(EX_OSERR, "Cannot allocate memory for events list");
  }

  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    warn("Cannot add socket to epoll set");
    return false;
  }

  connections.numfds++;
  return true;
}

static void epoll_leave(int epollfd, int fd) {
  if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) < 0)
    err(EX_OSERR, "Could not remove entry from epoll set");

  connections.numfds--;
}


static void cleanup_old_events(void) {
  if ((connections.numevents - 1024) > connections.numfds) {
    printf("Removing memory from connections\n");
    connections.numevents -= 1024;
    connections.events = realloc(connections.events,
      sizeof(connections.events)*connections.numevents);
  }
}


static void disconnect(int fd) {
  shutdown(fd, SHUT_RDWR);
  close(fd);
  return;
}

static bool read_and_reply(int fd) {
  char buf[128];
  int rc;
  int val;
  memset(buf, 0, sizeof(buf));

  if ((rc = recv(fd, buf, sizeof(buf), 0)) <= 0) {
    rc ? warn("Cannot read from socket") : 1;
    return false;
  }

  val = atoi(buf);
  if (val % 25 == 0)
    shutdown(fd, SHUT_RD);

  if (send(fd, buf, rc, MSG_NOSIGNAL) < 0) {
    warn("Cannot send to socket");
    return false;
  }

  return true;
}

int main()
{
  int srv = create_srv_socket("8558");
  int ep = create_epoll();
  int rc = -1;
  struct epoll_event *ev = NULL;

  if (!epoll_join(ep, srv, EPOLLIN)) 
    err(EX_OSERR, "Server cannot join epollfd");

  while (1) {
    int i, cli;

    rc = epoll_wait(ep, connections.events, connections.numfds, -1);
    if (rc < 0 && errno == EINTR)
      continue;
    else if (rc < 0)
      err(EX_OSERR, "Cannot properly perform epoll wait");

    for (i=0; i < rc; i++) {
      ev = &connections.events[i];

      if (ev->data.fd != srv) {

        if (ev->events & EPOLLIN) {
          if (!read_and_reply(ev->data.fd)) {
            epoll_leave(ep, ev->data.fd);
            disconnect(ev->data.fd);
          }
        } 

        if (ev->events & EPOLLERR || ev->events & EPOLLHUP) {
          if (ev->events & EPOLLERR)
            warn("Error in in fd: %d", ev->data.fd);
          else
            warn("Closing disconnected fd: %d", ev->data.fd);
  
          epoll_leave(ep, ev->data.fd);
          disconnect(ev->data.fd);
        }

      }
      else {

        if (ev->events & EPOLLIN) {
          if ((cli = accept(srv, NULL, 0)) < 0) {
            warn("Could not add socket");
            continue;
          }

          epoll_join(ep, cli, EPOLLIN);
        }

        if (ev->events & EPOLLERR || ev->events & EPOLLHUP)
          err(EX_OSERR, "Server FD has failed", ev->data.fd);
        
      }
    }

    cleanup_old_events();
  }

}
