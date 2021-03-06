#ifndef _COMMON_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <err.h>
#include <errno.h>
#include <syslog.h>
#include <sysexits.h>
#include <limits.h>

#include <libaudit.h>
#include <linux/audit.h>
#include <auparse.h>

#define PROGNAME "rwdisp"
#define UNIQ_FILTER_NAME "**added by " PROGNAME "**"

#define foreach_rule(r, e) \
  for (e=r->lh_first; e != NULL; e=e->entries.le_next)

LIST_HEAD(audit_rules, audit_rules_entry);
LIST_HEAD(watched_paths, path_counts);

struct audit_rules_entry {
  LIST_ENTRY(audit_rules_entry) entries;
  struct audit_rule_data rule;
};

struct path_counts {
  char path[PATH_MAX];
  int start;
  int reads;
  int writes;
  LIST_ENTRY(path_counts) entries;
};

auparse_state_t * parser_init(void *data);
void parser_parse_event(
    auparse_state_t *au,
    auparse_cb_event_t cb_event_type,
    void *data);
void controlsock_init();
#endif
