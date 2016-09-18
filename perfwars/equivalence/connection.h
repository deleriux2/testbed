#ifndef _CONNECTION_H
#define _CONNECTION_H
#include "common.h"
#include "http.h"

typedef struct connection {
  void *manager;
  int worker_number;

  int fd;
  ev_io io;
  gnutls_session_t tls;
  ev_tstamp last_activity;

  http_request_t *req;

  unsigned char *send_buffer;
  size_t send_length;
  off_t send_offset;

  unsigned char *recv_buffer;
  size_t recv_length;
  off_t recv_offset;

  struct connection *last;  
  struct connection *next;
} connection_t;


connection_t * connection_init(int fd, void *manager);
void connection_add(connection_t *c);
void connection_destroy(connection_t *c);
void connection_disconnect(connection_t *c);
#endif
