#include "common.h"
#include "database.h"
#include "connection.h"
#include "manager.h"
#include "http.h"
#include <time.h>
#include <ctype.h>

#define ACCEPTABLE_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghiojklmnopqrstuvwxyz0123456789_."
#define HEXADECIMAL_CHARS "abcdef0123456789"

#define HTTP_NOT_IMPLEMENTED "HTTP/1.1 501 Not Implemented\r\n" \
                             "Content-Type: text/plain\r\n" \
                             "Date: %s\r\n" \
                             "Server: "HTTP_SERVER_NAME"\r\n" \
                             "Connection: close\r\n" \
                             "Content-Length: 17\r\n" \
                             "\r\n" \
                             "Not Implemented\n"

#define HTTP_NOT_FOUND       "HTTP/1.1 404 Not Found\r\n" \
                             "Content-Type: text/plain\r\n" \
                             "Date: %s\r\n" \
                             "Server: "HTTP_SERVER_NAME"\r\n" \
                             "Connection: close\r\n" \
                             "Content-Length: 10\r\n" \
                             "\r\n" \
                             "Not Found\n"

#define HTTP_INTERNAL_SERVER_ERROR "HTTP/1.1 500 Internal Server Error\r\n" \
                                   "Content-Type: text/plain\r\n" \
                                   "Date: %s\r\n" \
                                   "Server: "HTTP_SERVER_NAME"\r\n" \
                                   "Connection: close\r\n" \
                                   "Content-Length: 22\r\n" \
                                   "\r\n" \
                                  "Internal Server Error\n"

#define HTTP_BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n" \
                                   "Content-Type: text/plain\r\n" \
                                   "Date: %s\r\n" \
                                   "Server: "HTTP_SERVER_NAME"\r\n" \
                                   "Connection: close\r\n" \
                                   "Content-Length: 12\r\n" \
                                   "\r\n" \
                                  "Bad Request\n"

#define HTTP_FORBIDDEN "HTTP/1.1 403 Forbidden\r\n" \
                                   "Content-Type: text/plain\r\n" \
                                   "Date: %s\r\n" \
                                   "Server: "HTTP_SERVER_NAME"\r\n" \
                                   "Connection: close\r\n" \
                                   "Content-Length: 10\r\n" \
                                   "\r\n" \
                                  "Forbidden\n"

#define HTTP_FOUND_FILE_RESPONSE "HTTP/1.1 200 OK\r\n" \
                                 "Content-Type: text/plain\r\n" \
                                 "Date: %s\r\n" \
                                 "Server: "HTTP_SERVER_NAME"\r\n" \
                                 "Connection: close\r\n" \
                                 "Content-Length: 65\r\n" \
                                 "\r\n" \
                                 "%s\n"

#define HTTP_FOUND_SHA_RESPONSE "HTTP/1.1 200 OK\r\n" \
                                 "Content-Type: application/octet-stream\r\n" \
                                 "Content-Disposition: attachment; filename=\"%s\"\r\n" \
                                 "Date: %s\r\n" \
                                 "Server: "HTTP_SERVER_NAME"\r\n" \
                                 "Connection: close\r\n" \
                                 "Content-Length: %d\r\n" \
                                 "\r\n" \
                                 "%s"



/* Converts a hex character to its integer value */
static char from_hex(
    char ch)
{
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

static char *url_decode(
    char *str)
{
  char *pstr = str, *buf = malloc(strlen(str) *2), *pbuf = buf;
  memset(buf, 0, strlen(str) *2);
  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
        *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else if (*pstr == '+') { 
      *pbuf++ = ' ';
    } else {
      *pbuf++ = *pstr;
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

static int acceptable_chars(
    char *c)
{
  int x = 0;
  char *p;

  for (p=c; *p != 0; p++) {
    if (strpbrk(p, ACCEPTABLE_CHARS))
      x++;
  }
  if (x != strlen(c))
    return 0;
  return 1;
}

static int is_hex(
    char *c)
{
  int x = 0;
  char *p;

  for (p=c; *p != 0; p++) {
    if (strpbrk(p, HEXADECIMAL_CHARS))
      x++;
  }
  if (x != strlen(c))
    return 0;
  return 1;
}



/* This isn't strictly \r\n because it would appear most webservers ignore
 * this requirement. Its just \n */
static int get_crlf(
    char *haystack,
    char *buffer,
    int len)
{
  char *p;

  p = strstr(haystack,"\n");
  if (!p)
    return 0;

  if (p-haystack+2 > len)
    return -1;

  p+=1;
  memcpy(buffer, haystack, (p-haystack));

  return p-haystack;
}



static void http_bad_request(
    unsigned char **makebuf,
    size_t *buflen)
{
  struct tm tm;
  time_t now;
  char b[1024];
  char date[48];

  memset(b, 0, sizeof(b));
  memset(date, 0, sizeof(date));

  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %y %h:%m:%s %z", &tm);

  *buflen = snprintf(b, 1023, HTTP_BAD_REQUEST, date);
  *makebuf = strdup(b);
}


static void http_forbidden(
    unsigned char **makebuf,
    size_t *buflen)
{
  struct tm tm;
  time_t now;
  char b[1024];
  char date[48];

  memset(b, 0, sizeof(b));
  memset(date, 0, sizeof(date));

  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %y %h:%m:%s %z", &tm);

  *buflen = snprintf(b, 1023, HTTP_FORBIDDEN, date);
  *makebuf = strdup(b);
}

static void http_not_found(
    unsigned char **makebuf,
    size_t *buflen)
{
  struct tm tm;
  time_t now;
  char b[1024];
  char date[48];

  memset(b, 0, sizeof(b));
  memset(date, 0, sizeof(date));

  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  *buflen = snprintf(b, 1023, HTTP_NOT_FOUND, date);
  *makebuf = strdup(b);
}

static void http_not_implemented(
    unsigned char **makebuf,
    size_t *buflen)
{
  struct tm tm;
  time_t now;
  char b[1024];
  char date[48];

  memset(b, 0, sizeof(b));
  memset(date, 0, sizeof(date));

  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  *buflen = snprintf(b, 1023, HTTP_NOT_IMPLEMENTED, date);
  *makebuf = strdup(b);
}

static void http_internal_server_error(
    unsigned char **makebuf,
    size_t *buflen)
{
  struct tm tm;
  time_t now;
  char b[1024];
  char date[48];

  memset(b, 0, sizeof(b));
  memset(date, 0, sizeof(date));

  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  *buflen = snprintf(b, 1023, HTTP_INTERNAL_SERVER_ERROR, date);
  *makebuf = strdup(b);
}


static void http_sha_request(
    http_request_t *req,
    char *sha, 
    unsigned char **makebuf,
    size_t *buflen)
{
  db_t *db;
  manager_t *m;
  connection_t *c;
  db_record_t *rec;
  struct tm tm;
  time_t now;
  char date[48];
  char shabin[32];
  char response[DB_MAX_DATA_SIZE+2048];


  c = req->connection;
  m = c->manager;
  db = m->db;
  
  int l = strlen(sha);
  if (l != 64) {
    http_not_found(makebuf, buflen);
    return;
  }

  if (!is_hex(sha)) {
    http_bad_request(makebuf, buflen);
    return;
  }

  /* Convert back to binary form */
  for (int i=0; i < 32; i++) {
    if (!sscanf(&sha[i*2], "%02hhx",&shabin[i])) {
     http_internal_server_error(makebuf, buflen);
     return;
    }
  }

  rec = database_get_sum(db, shabin);
  if (!rec) {
    http_not_found(makebuf, buflen);
    return;
  }

  /* We found the record */
  memset(response, 0, sizeof(response));
  memset(date, 0, sizeof(date));
  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %Y %H:%M:%S %Z", &tm);


  *buflen = snprintf(response, DB_MAX_DATA_SIZE+2048, HTTP_FOUND_SHA_RESPONSE,
                     rec->filename, date, rec->datalen, rec->data);
  *makebuf = strdup(response);
  database_record_free(rec);
}


static void http_files_request(
    http_request_t *req,
    char *filename, 
    unsigned char **makebuf,
    size_t *buflen)
{
  db_t *db;
  manager_t *m;
  connection_t *c;
  db_record_t *rec;
  char shadata[96];
  char response[1024];
  char *p;
  struct tm tm;
  time_t now;
  char date[48];

  c = req->connection;
  m = c->manager;
  db = m->db;
  

  int l = strlen(filename);
  if (l < 3 || l > 48) {
    http_not_found(makebuf, buflen);
    return;
  }

  l = strlen(filename);
  if (!acceptable_chars(filename)) {
    http_forbidden(makebuf, buflen);
    return;
  }

  rec = database_get_file(db, filename);
  if (!rec) {
    http_not_found(makebuf, buflen);
    return;
  }

  /* We found the record */
  memset(shadata, 0, 96);
  p = shadata;
  /* Convert to hexadecimal */
  for (int i=0; i < 32; i++) {
    snprintf(p, 3, "%02hhx", rec->sha[i]);
    p += 2;
  }

  memset(date, 0, sizeof(date));
  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %Y %H:%M:%S %Z", &tm);


  *buflen = snprintf(response, 1024, HTTP_FOUND_FILE_RESPONSE, date, shadata);
  *makebuf = strdup(response);
  database_record_free(rec);
}


static void http_submit_request(
    http_request_t *req,
    char *filename, 
    unsigned char **makebuf,
    size_t *buflen)
{
  db_t *db;
  manager_t *m;
  worker_t *w;
  connection_t *c;
  db_record_t *rec;
  char sha[32];
  char shadata[96];
  char response[1024];
  struct tm tm;
  time_t now;
  char date[48];
  char *data, *p;
  int l, rc;


  c = req->connection;
  m = c->manager;
  db = m->db;

  pthread_mutex_lock(&m->lock);
  w = m->workers[c->worker_number];
  pthread_mutex_unlock(&m->lock);
  

  l = strlen(filename);
  if (l < 3 || l > 48) {
    http_forbidden(makebuf, buflen);
    return;
  }

  l = strlen(filename);
  if (!acceptable_chars(filename)) {
    http_forbidden(makebuf, buflen);
    return;
  }

  /* Check it starts with 'data=' */
  if (strncmp(req->body, "data=", 5) != 0) {
    http_bad_request(makebuf, buflen);
    return;
  }

  /* Decode url */
  data = url_decode(&req->body[5]);
  if (!data) {
    http_internal_server_error(makebuf, buflen);
    return;
  }
  l = strlen(data);

  /* Make sure the record will fit */
  if (l > DB_MAX_DATA_SIZE || l < 10) {
    http_bad_request(makebuf, buflen);
    return;
  }

  /* Calculate sha sum */
  sha256_update(&w->sha_ctx, SHA256_KEYLEN, SHA256_KEY);
  sha256_update(&w->sha_ctx, l, data);
  sha256_digest(&w->sha_ctx, 32, sha);
 
  rc = database_insert(db, filename, sha, data, l, TYPE_DYNAMIC); 
  if (rc == -1) {
    http_forbidden(makebuf, buflen);
    return;
  }
  else if (rc == 0 || rc == -2) {
    http_internal_server_error(makebuf, buflen);
    return;
  }
  /* Error code -3 results in us responding like we did it.. */

  /* The record went in, hooray! Convert sha to hex */
  memset(shadata, 0, 96);
  p = shadata;
  for (int i=0; i < 32; i++) {
    snprintf(p, 3, "%02hhx", sha[i]);
    p += 2;
  }

  memset(date, 0, sizeof(date));
  now = time(NULL);
  localtime_r(&now, &tm);
  strftime(date, 47, "%a, %d %b %Y %H:%M:%S %Z", &tm);


  *buflen = snprintf(response, 1024, HTTP_FOUND_FILE_RESPONSE, date, shadata);
  *makebuf = strdup(response);
  free(data);
}


void http_request_destroy(
    http_request_t *req)
{
  http_header_t *hdr, *n;
  if (req) {
    if (req->method)
      free(req->method);
    hdr = req->hdrs;
    while (hdr) {
      n = hdr->next;
      free(hdr->name);
      free(hdr->value);
      free(hdr);
      hdr = n;
    }
    free(req->body);
    free(req);
  }
}

int http_request_parse(
    http_request_t *req,
    char *buffer)
{
  int rc;
  char *p;
  char line[1024];
  char name[512];
  char value[512];
  http_header_t *hdr, *n;
  int l;

  p = buffer + req->parsed_bytes;
  if (req->state == HTTP_PARSER_STATE_REQUEST) {

    memset(line, 0, sizeof(line));
    l = get_crlf(p, line, 1023);

    if (l <= 0)
      return l;

    rc = sscanf(line, "%ms %ms %ms\r\n", &req->method, &req->uri, &req->version);
    if (rc != 3)
      return -1; /* Bad request */

    req->parsed_bytes += l;
    p += l;
    req->state = HTTP_PARSER_STATE_HEADER;
  }

  if (req->state == HTTP_PARSER_STATE_HEADER) {
    memset(line, 0, sizeof(line));
    while ((l = get_crlf(p, line, 1023)) > 0) {
      if (l == 1 || l == 2) {
        req->state = HTTP_PARSER_STATE_BODY;

        /* Look for content length header and update */
        hdr = req->hdrs;
        while (hdr) {
          if (strcmp(hdr->name, "Content-Length") == 0) {
            req->content_length = atoi(hdr->value);
            /* Must be a valid integer */
            if (req->content_length == 0 && strlen(hdr->value) > 1) {
              req->content_length = -1;
              return -1; /* Bad request */
            }
            else if (req->content_length > 1048576) {
              req->content_length = -1;
              return -1;
            }
          }
          hdr = hdr->next;
        }

        goto body;
      }

      rc = sscanf(line, "%[^:]: %s\r\n", name, value);
      if (rc != 2)
        return -1;

      /* Add to the end of the header list */
      n = malloc(sizeof(http_header_t));
      if (!n)
        return -1; /* system error */
      n->name = strdup(name);
      n->value = strdup(value);
      n->next = NULL;

      if (req->hdrs) {
        hdr = req->hdrs;
        while (hdr->next) 
          hdr = hdr->next;
        hdr->next = n;
      }
      else {
        req->hdrs = n;
      }
      p += l;
      req->parsed_bytes += l;
      memset(line, 0, sizeof(line));
    }
    if (l <= 0)
      return l;
  }

body:

  /* Fetch the request body */
  if (req->state == HTTP_PARSER_STATE_BODY) {
    if (*p == '\r')
      p++;
    if (*p == '\n')
      p++;

    if (req->content_length > -1) {
      l = strlen(p);
      if (l >= req->content_length) {
        req->body = calloc(req->content_length+1, 1);
        memcpy(req->body, p, req->content_length);
        req->state = HTTP_PARSER_STATE_DONE;
        return 1;
      }
      else
        return 0;
    }
    else {
      memset(line, 0, 1024);
      l = get_crlf(p, line, 1023);

      req->body = calloc(l+1, 1);
      memcpy(req->body, line, l);
      req->state = HTTP_PARSER_STATE_DONE;
      return 1;
    }
  }

  return 0;
}


void http_generate_response(
    http_request_t *req,
    unsigned char **makebuf,
    size_t *makebuflen)
{
  int rc;
  char uri[512];

  memset(uri, 0, sizeof(uri));

  /* Determine the type of request first */
  if ((strcmp(req->method, "GET") == 0) || (strcmp(req->method, "HEAD") == 0))  {
    /* Parse the URI to see if its a supported request */
    rc = sscanf(req->uri, "/file/%s", uri);
    if (rc == 1) {
      http_files_request(req, uri, makebuf, makebuflen);
      return;
    }
    rc = sscanf(req->uri, "/sha/%s", uri);
    if (rc == 1) {
      http_sha_request(req, uri, makebuf, makebuflen);
      return;
    }
    else {
      http_not_found(makebuf, makebuflen);
    }
  }

  else if (strcmp(req->method, "POST") == 0) {
    rc = sscanf(req->uri, "/submit/%s", uri);
    if (rc == 1) {
      http_submit_request(req, uri, makebuf, makebuflen);
      return;
    }
    else {
      http_not_found(makebuf, makebuflen);
      return;
    }
  }

  else {
    http_not_implemented(makebuf, makebuflen);
  }
}

http_request_t * http_request_init(
    void *data)
{
  http_request_t *req = NULL;
  req = malloc(sizeof(http_request_t));
  if (!req)
    return NULL;

  memset(req, 0, sizeof(http_request_t));

  req->parsed_bytes = 0;
  req->content_length = -1;
  req->connection = data;

  return req;
}

