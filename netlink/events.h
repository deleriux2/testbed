#ifndef _EVENTS_H
#define _EVENTS_H

#define EVENT_MAX 512

void event_init(void);
int event_add(int fd, int mode, int (*event_cb)(void *), void *data, int datalen);
int event_del(int fd);
int event_loop(void);
#endif
