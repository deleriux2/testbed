#include "common.h"

#include <syscall.h>

static int audit_get_rules(
    int fd,
    struct audit_rules **rules)
{
  struct audit_reply rep;
  int rc;
  int len=0;
  struct audit_rules *head = malloc(sizeof(struct audit_rules));
  struct audit_rules_entry *ent;

  if (!head)
    return -1;
  LIST_INIT(head);

  if (audit_request_rules_list_data(fd) < 0)
    return -1;

  do {
    rc = audit_get_reply(fd, &rep, GET_REPLY_BLOCKING, 0);
    if (!NLMSG_OK(rep.nlh, rc))
      goto fail;

    if (rep.type != AUDIT_LIST_RULES)
      continue;

    ent = malloc(sizeof(*ent)+rep.ruledata->buflen);
    if (!ent)
      goto fail;

    memcpy(&ent->rule, rep.ruledata, sizeof(*rep.ruledata)+rep.ruledata->buflen);
    LIST_INSERT_HEAD(head, ent, entries);
    len++;    
  } while (rep.type != NLMSG_DONE);

  *rules = head;
  return len;

fail:
  if (head) {
    while (head->lh_first != NULL) {
      ent = head->lh_first;
      LIST_REMOVE(head->lh_first, entries);
      free(ent);
    }
    free(head);
  }
  return -1;
}


/* Adds syscalls we need to monitor */
int audit_setup_syscalls(
  int fd,
  char *path)
{
  char success[] = "success=1";
  char arch[] = "arch=b64";
  char key[] = "key=" UNIQ_FILTER_NAME;
  char dir[PATH_MAX] = "dir=";
  strncat(dir, path, PATH_MAX-5);

  struct audit_rule_data *rule = malloc(sizeof(*rule));
  if (!rule)
    goto fail;
  memset(rule, 0, sizeof(*rule));

  /* BUG: Shouldn't really need this just to set a filter */
  if (audit_rule_syscallbyname_data(rule, "open") < 0)
    goto fail;
  if (audit_rule_syscallbyname_data(rule, "lstat") < 0)
    goto fail;
  if (audit_rule_syscallbyname_data(rule, "access") < 0)
    goto fail;
  
  rule->flags |= AUDIT_FILTER_PREPEND;
  if (audit_rule_fieldpair_data(&rule, dir, AUDIT_FILTER_EXIT) < 0)
    goto fail;
  if (audit_rule_fieldpair_data(&rule, success, AUDIT_FILTER_EXIT) < 0)
    goto fail;
  if (audit_rule_fieldpair_data(&rule, arch, AUDIT_FILTER_EXIT) < 0)
    goto fail; 
  if (audit_rule_fieldpair_data(&rule, key, AUDIT_FILTER_EXIT) < 0)
    goto fail;

  if (audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS) < 0)
    goto fail;

  audit_rule_free_data(rule);
  return 0;

fail:
  if (rule)
    audit_rule_free_data(rule);
  return -1;
}


/* Iterate through the list of active rules and remove those that match out unique key */
int audit_teardown_syscalls(
  int fd)
{
  int rc, len=0;
  struct audit_rules *rules = NULL;
  struct audit_rules_entry *ent;
  char *p;
  int i;
  rc = audit_get_rules(fd, &rules);

  if (!rc) 
    return 0;

  foreach_rule(rules, ent) {
    p = ent->rule.buf;
    for (i=0; i < ent->rule.field_count; i++) {
      if (ent->rule.fields[i] == AUDIT_FILTERKEY) {
        if (strncmp(p, UNIQ_FILTER_NAME, ent->rule.values[i]) == 0) {
          if (audit_delete_rule_data(fd, &ent->rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS) <= 0)
            warn("Rule delete failure. You should flush the audit rules using auditctl");
          len++;
        }
      }
      /* These fields represent string values and must adjust the buffer accordingly. */
      switch(ent->rule.fields[i]) {
        case AUDIT_SUBJ_USER...AUDIT_SUBJ_CLR:
        case AUDIT_OBJ_USER...AUDIT_OBJ_LEV_HIGH:
        case AUDIT_WATCH:
        case AUDIT_DIR:
        case AUDIT_FILTERKEY:
          p += ent->rule.values[i];
        break;
      }        
    }
  }

  /* Ditch the rules list */
  if (rules) {
    while (rules->lh_first != NULL) {
      ent = rules->lh_first;
      LIST_REMOVE(rules->lh_first, entries);
      free(ent);
    }
    free(rules);
  }
  return len;
}



