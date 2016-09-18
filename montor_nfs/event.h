#ifndef _EVENT_H_
#define _EVENT_H_
#include <sys/epoll.h>

#define EVENT_MAXFDS 256

void event_init(void);
/* Returns number of events handled or -1 on error */
int event_loop(int max, int timeout);
void event_del_fd(int fd);
int event_mod_event(int fd, int event);
int event_add_fd(
                int fd,
                int (*callback)(int fd, int event, void *data),
                void (*destroy),
                void *data,
                int event);
#endif
