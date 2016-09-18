#ifndef _CONNECTION_H
#define _CONNECTION_H
#include "manager.h"
#include "worker.h"

void connection_start_connect(worker_t *w, connection_t *c);
void connection_disconnect(worker_t *w, connection_t *c);
void connection_clear_buffers(connection_t *c);
#endif
