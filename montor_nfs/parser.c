#include "common.h"
#include <auparse.h>
#include <limits.h>

extern int running;
static char field[8192];

static inline char * field_noquotes(
    const char *in)
{
  memset(field, 0, 8192);
  strncpy(field, &in[1], strlen(in)-2);
  return field;
}

void parser_parse_event(
    auparse_state_t *au,
    auparse_cb_event_t cb_event_type,
    void *data)
{
  char path[PATH_MAX];
  char syscall[32];
  const char *key;
  const char *p1, *p2;
  int a1;
  struct watched_paths *wpaths = data;
  struct path_counts *pc;

  if (cb_event_type == AUPARSE_CB_EVENT_READY) {
    if (auparse_first_record(au) <= 0) 
      return;

    /* See if the record is something we care for by looking for our key */
    key = auparse_find_field(au, "key");
    if (!key)
      return;
    key = auparse_interpret_field(au);
    if (strcmp(key, UNIQ_FILTER_NAME) != 0)
      return;
    auparse_first_record(au);

    /* Get the path being recorded */
    p1 = auparse_find_field(au, "cwd");
    if (!p1)
      return;

    p2 = auparse_find_field(au, "name");
    if (!p2)
      return;

    memset(path, 0, sizeof(path));
    if (p2[1] == '/') {
      snprintf(path, PATH_MAX, "%s", field_noquotes(p2));
    }
    else {
      snprintf(path, PATH_MAX, "%s/%s", field_noquotes(p1), field_noquotes(p2));
    }
    auparse_first_record(au);
 
    /* See if the path is in our list of those we watch */
    for (pc = wpaths->lh_first; pc != NULL; pc = pc->entries.le_next) {
      if (strncmp(pc->path, path, strlen(pc->path)) == 0) {
        /* Get the syscall being used */
        p1 = auparse_find_field(au, "syscall");
        if (!p1)
          return;
        p1 = auparse_interpret_field(au);
        strncpy(syscall, p1, 32);
        auparse_first_record(au);

        /* If the syscall is open, get the args */
        if (strncmp(syscall, "open", 32) == 0) {
          p1 = auparse_find_field(au, "a1");
          a1 = strtol(p1, NULL, 16);
          if (a1 & (O_WRONLY|O_RDWR))
            pc->writes++;
          else if ((a1 & O_RDONLY) == 0)
            pc->reads++;
        }
        else if (strncmp(syscall, "access", 32) == 0) {
          pc->reads++;
        }
        else if (strncmp(syscall, "lstat", 32) == 0) {
          pc->reads++;
        }
        /* We dont break. Any matching subtree gets a shot. */
      }
    }
  }
}

auparse_state_t * parser_init(
    void *data)
{
  auparse_state_t *parser = NULL;
  if ((parser = auparse_init(AUSOURCE_FEED, data)) == NULL) {
    syslog(LOG_ERR, "Could not initialize parser: %s", strerror(errno));
    exit(1);
  }

  return parser;
}


