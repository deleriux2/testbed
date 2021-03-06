#include "common.h"
#include "config.h"

extern int yyparse();
extern FILE *yyin;

struct config *configuration = NULL;

static void config_destroy_instance(
  struct config *conf)
{
  if (!conf)
    return;
  if (conf->name)
    free(conf->name);
  if (conf->interface)
    free(conf->interface);
  free(conf);
}

struct config * config_new(
  void)
{
  struct config *c = NULL, *tmp = NULL;
  c = malloc(sizeof(*c));
  if (!c)
    return NULL;

  memset(c, 0, sizeof(*c));
  /* Set some defaults */
  strncpy(c->interface, "lo", 128);
  inet_pton(AF_INET, "224.0.0.50", &c->mcast_addr.sin_addr.s_addr);
  c->mcast_addr.sin_family = AF_INET;
  c->mcast_addr.sin_port = htons(3456);
  c->local_addr.sin_family = AF_INET;
  c->group = 0;
  c->payloadsz = 80;

  if (!configuration) {
    configuration = c;
  }
  else {
    for (tmp = configuration; tmp->next != NULL; tmp=tmp->next);
    tmp->next = c;
  }

  return c;
}


void config_destroy(
  void)
{
  struct config *tmp, *next;
  for (tmp=configuration; tmp != NULL; tmp=tmp) {
    next = tmp->next;
    config_destroy_instance(tmp);
    tmp = next;
  }
}


int config_parse(
  char *name)
{
  int rc;
  int l = strlen(name);
  FILE *config_file = NULL;
  assert(l < PATH_MAX && l > 1);

  config_file = fopen(name, "r");
  if (!config_file) {
    perror("Could not open config file");
    return -1;
  }

  yyin = config_file;

  do {
    rc = yyparse();
  } while (!feof(yyin) && !rc);
  fclose(config_file);


  if (!rc)
    return 0;
  else
    return -1;
}



