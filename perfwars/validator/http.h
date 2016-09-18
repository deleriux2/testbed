#ifndef _HTTP_H
#define _HTTP_H
#include "common.h"
#include "manager.h"
#include "worker.h"

struct http_hdr {
  char *name;
  char *value;
  struct http_hdr *next;
};

typedef struct http_response {
  int errcode;
  char errmsg[128];
  int content_length;
  struct http_hdr *hdrs;
  char *body;
} http_response_t;

int http_generate_record(connection_t *c);
int http_validate(connection_t *c);
void http_response_destroy(http_response_t *resp);

#endif
