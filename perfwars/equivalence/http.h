#ifndef _HTTP_H
#define _HTTP_H

#define HTTP_PARSER_STATE_REQUEST 0
#define HTTP_PARSER_STATE_HEADER  1
#define HTTP_PARSER_STATE_BODY    2
#define HTTP_PARSER_STATE_DONE    3

#define HTTP_SERVER_NAME "Equivalence"

typedef struct http_header {
  char *name;
  char *value;
  struct http_header *next;
} http_header_t;

typedef struct http_request {
  void *connection;

  int state;
  int parsed_bytes;

  char *method;
  char *uri;
  char *version;

  http_header_t *hdrs;

  int content_length;

  char *body;
} http_request_t;


http_request_t * http_request_init(void *data);
void http_request_destroy(http_request_t *req);
int http_request_parse(http_request_t *req, char *buffer);
void http_generate_response(http_request_t *req, unsigned char **buffer, size_t *len);

#endif
