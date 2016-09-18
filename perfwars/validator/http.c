#include <ctype.h>
#include <nettle/sha2.h>
#include "database.h"
#include "http.h"

#define GET_SHA_REQUEST "GET /sha/%s HTTP/1.1\r\n" \
                        "Host: %s\r\n" \
                        "Connection: close\r\n" \
                        "User-Agent: perfwars_2016\r\n" \
                        "\r\n"

#define GET_FILE_REQUEST "GET /file/%s HTTP/1.1\r\n" \
                         "Host: %s\r\n" \
                         "Connection: close\r\n" \
                         "User-Agent: perfwars_2016\r\n" \
                         "\r\n"

#define PUT_REQUEST "POST /submit/%s HTTP/1.1\r\n" \
                    "Host: %s\r\n" \
                    "Connection: close\r\n" \
                    "User-Agent: perfwars_2016\r\n" \
                    "Content-Type: application/x-www-form-urlencoded\r\n" \
                    "Content-Length: %d\r\n" \
                    "\r\n" \
                    "data=%s"


static char * generate_random_filename(
    int *seed)
{
  int len = (rand_r(seed) % 6) + 9;
  char *buf = malloc(len+4+1);
  memset(buf, 0, len+4+1);
  char c;
  for (int i=0; i < len; i++) {
    c = (char)((rand_r(seed) % 26) + 97);
    buf[i] = c;
  }
  strcat(buf, ".dat");
  return buf;
}

/* Converts a hex character to its integer value */
static char from_hex(
    char ch)
{
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
static char to_hex(
    char code)
{
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}


/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
static char *url_encode(
    char *str) 
{
  char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  memset(buf, 0, strlen(str) * 3 + 1);
  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
      *pbuf++ = *pstr;
    else if (*pstr == ' ') 
      *pbuf++ = '+';
    else 
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(
    char *str)
{
  char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
  memset(buf, 0, strlen(str) + 1);
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


static int http_generate_put_record(
    connection_t *c)
{
  manager_t *m = c->manager;
  worker_t *w = c->worker;
  int offset = rand_r(&w->seed) % (m->canvas_sz - MAX_FILESIZE);
  int len = rand_r(&w->seed) % (MAX_FILESIZE-MIN_FILESIZE) + MIN_FILESIZE;
  int sz;

  char request_str[(MAX_FILESIZE)*3+1024];
  char *buf = calloc(len+32, 1);
  char *encoded;
  char *random_fname = generate_random_filename(&w->seed);
  memcpy(buf, &m->canvas[offset], len);
  encoded = url_encode(buf);

  memset(request_str, 0, (MAX_FILESIZE*3)+1024);
  sz = snprintf(request_str, (MAX_FILESIZE*3) + 1024, PUT_REQUEST, random_fname, m->hostname, 
           strlen(encoded) + 5, encoded);
  free(encoded);

  if (c->send_buffer)
    free(c->send_buffer);
  c->send_buffer_offset = 0;
  c->send_buffer_len = sz;
  c->send_buffer = strdup(request_str);
  c->canvas_offset = offset;
  c->canvas_len = len;
  c->canvas_filename = random_fname;

  return 0;
}

static int http_generate_get_sha_record(
    connection_t *c)
{
  manager_t *m = c->manager;
  worker_t *w = c->worker;
  db_t *db = m->db;
  db_record_t *rec;
  char shahex[68];
  memset(shahex, 0, 68);
  char request_str[1024];
  memset(request_str, 0, 1024);
  int sz;

  rec = database_get_random(db, &w->seed);
  if (!rec)
    return -1;

  for (int i=0; i < 32; i++) {
    snprintf(&shahex[i*2], 3, "%02hhx", rec->sha[i]);
  }

  sz = snprintf(request_str, 1024, GET_SHA_REQUEST, shahex, m->hostname);
  c->send_buffer_offset = 0;
  c->send_buffer_len = sz;
  c->send_buffer = strdup(request_str);
  c->canvas_sha = strdup(shahex);

  database_record_free(rec);
  return 0;
}


static int http_generate_get_file_record(
    connection_t *c)
{
  manager_t *m = c->manager;
  worker_t *w = c->worker;
  db_t *db = m->db;
  db_record_t *rec;
  char request_str[1024];
  memset(request_str, 0, 1024);
  int sz;

  rec = database_get_random(db, &w->seed);
  if (!rec)
    return -1;

  sz = snprintf(request_str, 1024, GET_FILE_REQUEST, rec->filename,
                m->hostname);
  c->send_buffer_offset = 0;
  c->send_buffer_len = sz;
  c->send_buffer = strdup(request_str);
  c->canvas_filename = strdup(rec->filename);

  database_record_free(rec);
  return 0;
}

static int http_validate_get_sha_record(
    connection_t *c,
    http_response_t *resp)
{
  struct http_hdr *hdr;
  db_record_t *rec;
  worker_t *w = c->worker;
  manager_t *m = c->manager;
  int valid=0;
  int rc;
  char filename[128];
  char sha[32];
  struct sha256_ctx s256;
  memset(filename, 0, 128);

  /* Error code invalid */
  if (resp->errcode != 200)
    return -2;

  /* Check if the headers provide a correct content
   * type and dispotion */
  for (hdr=resp->hdrs; hdr != NULL; hdr=hdr->next) {
    if(strcmp(hdr->name, "Content-Type") == 0) {
      if (strcmp(hdr->value, "application/octet-stream") == 0) {
        valid++;
      }
    }
    else if (strcmp(hdr->name, "Content-Disposition") == 0) {
      rc = sscanf(hdr->value, "attachment; filename=\"%128[^\"]\"", filename);
      if (rc == 1)
        valid++;
    }
    if (valid == 2)
      break;
  }

  /* Headers were invalid */
  if (valid != 2) {
    return -3;
  }

  /* Check if the filename for the record matches */
  rec = database_get_file(m->db, filename);
  if (!rec) {
    return -4;
  }

  /* Perform a shasum of the request body */
  sha256_update(&w->sha_ctx, SHA256_KEYLEN, SHA256_KEY);
  sha256_update(&w->sha_ctx, resp->content_length, resp->body);
  sha256_digest(&w->sha_ctx, 32, sha);

  /* Compare shas */
  if (memcmp(sha, rec->sha, 32) != 0) 
    return -1;

  database_record_free(rec);
  return 0;
}

static int http_validate_get_file_record(
    connection_t *c,
    http_response_t *resp)
{
  worker_t *w = c->worker;
  manager_t *m = w->manager;
  db_record_t *rec;

  struct http_hdr *hdr;
  char shahex[65];
  char sha[32];
  char cmpsha[32];

  memset(shahex, 0, 65);
  if (resp->errcode != 200) 
    return -1;

  if (resp->content_length != 65)
    return -1;
  for (hdr=resp->hdrs; hdr != NULL; hdr = hdr->next) {
    if (strcmp("Content-Type", hdr->name) == 0) {
      if (!strstr(hdr->value, "text/plain"))
        return -1;
      break;
    }
  }

  /* Fetch the hex and convert to binary */
  strncpy(shahex, resp->body, 64);
  for (int i=0; i < 32; i++) {
    if (sscanf(&shahex[i*2],"%02hhx", &sha[i]) != 1) 
      return -1;
  }

  /* Fetch record from db */
  if (!(rec = database_get_file(m->db, c->canvas_filename)))
    return -1;

/*
  printf("Filename: %s\n", c->canvas_filename);
  printf("Theirs: %s\n", shahex);
  printf("Ours:   ");
  for (int i=0; i<32; i++) {
    printf("%02hhx", rec->sha[i]);
  }
  printf("\n");
*/
  if (memcmp(rec->sha, sha, 32) != 0)
    return -1;

  database_record_free(rec);
  return 0;
}


static int http_validate_put_record(
    connection_t *c,
    http_response_t *resp)
{
  int rc;
  worker_t *w = c->worker;
  manager_t *m = w->manager;
  struct http_hdr *hdr;
  char shahex[65];
  char sha[32];
  char cmpsha[32];

  memset(shahex, 0, 65);
  if (resp->errcode != 200)
    return -1;

  if (resp->content_length != 65)
    return -1;
  for (hdr=resp->hdrs; hdr != NULL; hdr = hdr->next) {
    if (strcmp("Content-Type", hdr->name) == 0) {
      if (!strstr(hdr->value, "text/plain"))
        return -1;
      break;
    }
  }

  /* Fetch the hex and convert to binary */
  strncpy(shahex, resp->body, 64);
  for (int i=0; i < 32; i++) {
    if (sscanf(&shahex[i*2],"%02hhx", &sha[i]) != 1) 
      return -1;
  }

  sha256_update(&w->sha_ctx, SHA256_KEYLEN, SHA256_KEY);
  sha256_update(&w->sha_ctx, c->canvas_len, &m->canvas[c->canvas_offset]);
  sha256_digest(&w->sha_ctx, 32, cmpsha);
  char canvasdata[100*1024];
  if (memcmp(cmpsha, sha, 32) != 0) {
    return -1;
  }

  /* Insert into DB */
  rc = database_insert(m->db, c->canvas_filename, sha, 
                 c->canvas_offset, c->canvas_len, TYPE_DYNAMIC);
  if (!rc)
    return -1;

  return 0;
}

int http_generate_record(
    connection_t *c)
{
  worker_t *w = c->worker;
  int method = rand_r(&w->seed) % 4;
  c->method = method;
  if (method < 2)
    return http_generate_put_record(c);
  else if (method == 2)
    return http_generate_get_file_record(c);
  else if (method == 3)
    return http_generate_get_sha_record(c);

  return 0;
}


int http_validate(
    connection_t *c)
{
  manager_t *m = c->manager;
  worker_t *w = c->worker;
  char *p = c->recv_buffer;
  int rc=-1;
  struct http_hdr *h, *o;
  http_response_t *resp = malloc(sizeof(http_response_t));
  memset(resp, 0, sizeof(*resp));
  resp->content_length = -1;

  /* Parse the HTTP response */
  rc = sscanf(p, "HTTP/1.1 %d %128[^\r]\r\n", &resp->errcode, resp->errmsg);
  if (rc != 2) {
    rc = -10;
    goto fail;
  }
 
  /* Parse the headers */
  while ((p = strstr(p, "\r\n"))) {
    p+=2;
    h = malloc(sizeof(*h));
    h->next = NULL;
    h->name = NULL;
    h->value = NULL;

    rc = sscanf(p, "%m[^\r\n:]: %m[^\r]\r\n", &h->name, &h->value);
    if (rc == 2) {
      o = resp->hdrs;
      if (!o) 
        resp->hdrs = h;
      else {
        while (o) {
          if (o->next)
            o=o->next;
          else {
            o->next = h;
            break;
          }
        }
      }
    }
    else if (rc == 0) {
      rc = -1;
      free(h);
      break;
    }
    else if (rc == 1) {
      rc = -20;
      free(h->name);
      free(h->value);
      free(h);
      goto fail;
    }
  }

  p+=2;
  resp->body = strdup(p);

  /* As a post-processing step, grab the content length and compare it with the body */
  h = resp->hdrs;
  while (h) {
    if (strncmp("Content-Length", h->name, 14) == 0) {
      resp->content_length = atoi(h->value);
      break;
    }
    h = h->next;
  }
  if (resp->content_length < 0 || resp->content_length != strlen(resp->body)) {
    rc = -30;
    goto fin;
  }

  /* Pass the response onto the request validator */
  switch (c->method){
    case 0:
    case 1:
      rc = http_validate_put_record(c, resp);
    break;

    case 2:
      rc = http_validate_get_file_record(c, resp);
    break;

    case 3:
      rc = http_validate_get_sha_record(c, resp);
    break;
    default:
    break;
  }

//  if (rc != 0) {
//    printf("%s\n", c->send_buffer);
//    printf("%s\n", c->recv_buffer);
//  }

fin:
  c->resp = resp;
  return rc;

fail:
  if (resp) {
    h = resp->hdrs;
    while (h) {
      o = h;
      h = h->next;
      free(o->name);
      free(o->value);
      free(o);
    }
    free(resp);
  }
  return rc;
}


void http_response_destroy(
  http_response_t *resp)
{
  struct http_hdr *h, *o;
  if (resp) {
    h = resp->hdrs;
    while (h) {
      o = h;
      h = h->next;
      free(o->name);
      free(o->value);
      free(o);
    }
    free(resp);
  }
}
