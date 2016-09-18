#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <Uri.h>

static char * get_uripath(UriPathSegmentA *path) {
  char *result = calloc(1, 2048);
  char *r = result;
  int len;
  UriPathSegmentA *tmp = path;

  for (tmp=path; tmp != NULL; tmp=tmp->next) {
    *r = '/';
    r += 1;
    strncpy(r, tmp->text.first, tmp->text.afterLast - tmp->text.first);
    r += tmp->text.afterLast - tmp->text.first;
    if (r-result > 2048) {
      fprintf(stderr, "Path too big to resolve!\n");
      return NULL;
    }
  }
  return result;
}


int main(const int argc, const char **argv) {
  UriParserStateA state;
  UriUriA uri;
  UriQueryListA *querys;
  int items;

  memset(&uri, 0, sizeof(uri));
  state.uri = &uri;

  char *scheme = NULL;
  char *host = NULL;
  char *port = NULL;
  char *user = NULL;
  char *path = NULL;
  char *query = NULL;

  if (argc < 2) {
    fprintf(stderr, "Must pass a uri to parse\n");
    goto fail;
  }

  if (uriParseUriA(&state, argv[1]) != URI_SUCCESS) {
    fprintf(stderr, "Failed to parse URI\n");
    goto fail;
  }

  if (uri.query.afterLast-uri.query.first != 0) {
    if (uriDissectQueryMallocA(&querys, &items, uri.query.first, uri.query.afterLast) != URI_SUCCESS) { 
      fprintf(stderr, "Unable to parse query string\n");
      goto fail;
    }
  }

  scheme = strndup(uri.scheme.first, uri.scheme.afterLast-uri.scheme.first);
  host = strndup(uri.hostText.first, uri.hostText.afterLast-uri.hostText.first);
  port = strndup(uri.portText.first, uri.portText.afterLast-uri.portText.first);
  user = strndup(uri.userInfo.first, uri.userInfo.afterLast-uri.userInfo.first);
  path = get_uripath(uri.pathHead);
  query = strndup(uri.query.first, uri.query.afterLast-uri.query.first);

  printf("Scheme: %s\n", scheme);
  printf("User: %s\n", user);
  printf("Host: %s\n", host);
  printf("Port: %s\n", port);
  printf("Path: %s\n", path);
  printf("Query: %s\n", query);

  printf("Broken down query:\n");
  UriQueryListA *tmp;
  for (tmp=querys; tmp != NULL; tmp=tmp->next) {
    printf("  Key: %s, Value: %s\n", tmp->key, tmp->value);
  }

  return 0;

fail:
  uriFreeUriMembersA(&uri);
  return 1;
}
