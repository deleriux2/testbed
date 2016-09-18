#include "common.h"
#include "events.h"
#include "timer.h"

#include <sys/timerfd.h>


struct timer_cb {
  int fd;
  int (*event_cb)(void *data);
  void *data;
  int datalen;
  char oneshot;
};

struct timer_cb *cbs[TIMER_MAX];


static int timer_recv(
  void *data)
{
  struct timer_cb *cb = (struct timer_cb *)data;
  uint64_t buf;
  if (read(cb->fd, &buf, sizeof(buf)) < 0)
    goto fail;

  if (cb->event_cb(cb->data) < 0)
    goto fail;
  if (cb->oneshot) {
    timer_del(cb->fd);
  }

  return 1;

fail:
  timer_del(cb->fd);
  return -1;
}


int timer_add(
  int centisecs,
  int (*event_cb)(void *),
  void *data,
  int datalen,
  char oneshot)
{
  int eno;
  int fd = -1;
  struct timer_cb *cb = NULL;
  struct itimerspec it;

  assert(event_cb);
  assert(datalen >= 0);
  assert(centisecs > 0);

  cb = malloc(sizeof(*cb));
  if (!cb)
    goto fail;

  if (data) {
    cb->data = malloc(datalen);
    if (!cb->data)
      goto fail;
    memcpy(cb->data, data, datalen);
    cb->datalen = datalen;
  }
  else {
    cb->datalen = 0;
  }

  cb->oneshot = oneshot;
  cb->event_cb = event_cb;

  /* Convert time to timer spec */
  it.it_value.tv_sec = centisecs / 100;
  it.it_value.tv_nsec = (centisecs % 100) * 10000000;
  if (oneshot) {
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_nsec = 0;
  }
  else {
   it.it_interval.tv_sec = it.it_value.tv_sec;
   it.it_interval.tv_nsec = it.it_value.tv_nsec;
  }

  /* Allocate timerfd */
  if ((fd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0)
    goto fail;
  cb->fd = fd;

  /* Max timers reached */
  if (cb->fd >= TIMER_MAX) {
    errno = E2BIG;
    goto fail;
  }

  if (timerfd_settime(fd, 0, &it, NULL) < 0)
    goto fail;

  cbs[fd] = cb;

  if (event_add(fd, EPOLLIN, timer_recv, cb, sizeof(*cb)) < 0)
    goto fail;

  return fd;

fail:
  eno = errno;
  if (fd >= 0)
    close(fd);
  if (cb)
    if (cb->data)
      free(cb->data);
    free(cb);
  errno = eno;
  event_del(fd);
  return -1;
}


int timer_del(
  int fd)
{
  if (!cbs[fd])
    return -1;

  if (cbs[fd]->data)
    free(cbs[fd]->data);

  /* Dont care if this fails */
  event_del(fd);

  free(cbs[fd]);
  cbs[fd] = NULL;
  close(fd);
  return 1;
}
