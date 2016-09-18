#ifndef _QUEUE_H_
#define _QUEUE_H_

#include <pthread.h>
#include <sys/queue.h>

typedef struct queue * queue_t;

/* Initialize queue, with a limit in size */
queue_t queue_init(int);

void queue_destroy(queue_t);

void * queue_put(queue_t, void *);

void * queue_get(queue_t);

void queue_empty(queue_t);

#endif
