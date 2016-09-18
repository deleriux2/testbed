#include "someirc.h"
#include "message.h"

#include <pcre.h>

#define MESSAGE_MATCH 0
#define MATCH_NICKNAME 1
#define MATCH_HOSTNAME 2
#define MATCH_USER 3
#define MATCH_KEY 4
#define MAX_PCRES 1024

pcre *regexps[MAX_PCRES];

/* Regular expressions used for capturing terminators */
const char *strregexps[] = {
  /* The main message matching expression, is generic, further termination 
   * should occur */
  "^(:([^\r\n: ]{1,512}) )?([a-zA-Z]{1,510}|[0-9]{3})( [^\r\n:]{1,512})?( :(.{1,512}))?\r\n$",
  "^[a-zA-Z\\;\\[\\]\\\\`_^\\{\\|\\}][0-9a-zA-Z\\;\\[\\]\\\\`_^\\{\\|\\}]{0,MAXNICK}$",
  "^([a-zA-Z0-9][a-zA-Z0-9-]*[0-9a-zA-Z]\\.)+[a-zA-Z0-9][a-zA-Z0-9-]*[0-9a-zA-Z]$",
  "^[^\r\n @]$",
  "^\S+$",
  NULL,
};

/* Static prototypes */
static int match_message(const char *src, char *prefix, char *command, char *parameters, char *trailer);
static int match_target(const char *src);
static int match_nickname(const char *src);
static int match_servername(const char *src);
static int match_server(const char *src);
static int match_hostname(const char *src);



/* Loads up the list of regular expressions */
void message_init(
  void)
{
  memset(regexps, 0, sizeof(*regexps));
  const char *errptr;
  int erroffset;
  int i;
  for (i=0; strregexps[i] != NULL; i++) {
    regexps[i] = pcre_compile(strregexps[i], 0, &errptr, &erroffset, NULL);
    if (regexps[i] == NULL) {
      errx(EX_SOFTWARE, "Cannot compile regular expression %d, at character %d: %s",
            i, erroffset, errptr);
    }
  }
  return;
}


/* Match a 'target' entry */
static int match_target(
    const char *str)
{
  if (match_nickname(str) || match_server(str))
    return 1;
  return 0;
}


/* Match a 'nickname' entry */
static int match_nickname(
    const char *str)
{
  int rc;
  rc = pcre_exec(
    regexps[MATCH_NICKNAME],
    NULL, str, strlen(str),
    0, 0, NULL, 0);

  if (rc < 0)
    return 0;
  else
   return 1;
}


/* Match a 'server' entry */
static int match_server(
    const char *str)
{
  return match_servername(str);
}


/* Match a 'servername' entry */
static int match_servername(
    const char *str)
{
  return match_hostname(str);
}


/* Match a 'hostname' entry */
static int match_hostname(
    const char *str)
{
  int rc;
  rc = pcre_exec(
    regexps[MATCH_HOSTNAME],
    NULL, str, strlen(str),
    0, 0, NULL, 0);

  if (rc < 0)
    return 0;
  else
    return 1;
}


/* Match and returns the 'base' protocol or errors */
static int match_message(
  const char *src,
  char *prefix,
  char *command,
  char *parameters,
  char *trailer)
{
  int ovector[30];
  int i;
  int rc;
  rc = pcre_exec(
    regexps[MESSAGE_MATCH], 
    NULL, 
    src,
    strlen(src), 
    0,
    0,
    ovector,
    30);

  if (rc < 0) {
    printf("Bad match \"%s\"", src);
    return -1;
  }

  pcre_copy_substring(src, ovector, rc, 2, prefix, 512);
  pcre_copy_substring(src, ovector, rc, 3, command, 512);
  pcre_copy_substring(src, ovector, rc, 4, parameters, 512);
  pcre_copy_substring(src, ovector, rc, 5, trailer, 512);
  return 0;
}


extern char servername[64];

int message_parse(
    const char *str, 
    int len,
    msg_t *msg)
{
  assert(str);
  assert(msg);

  char params[512*14];
  char trailer[512];
  int i;
  char *p, *t;

  memset(params, 0, sizeof(params));
  memset(trailer, 0, sizeof(trailer));

  if (match_message(str, msg->prefix, msg->command, params, trailer) < 0) {
    /* Silently discard messages that dont make any sense to us */
    return 0;
  }

  /* Split params by " " and copy into param array */
  i=0;
  t = params;
  while ((p = strtok(t, " ")) != NULL) {
    strncpy(msg->params[i++], p, 512);    
    t = NULL;
  }
  if (i) {
    strncpy(msg->params[i++], trailer, 512);
  }
  msg->paramno = i;

  printf("OK\n");
  return 0;
}

/* Push a message onto the send fifo */
int message_push(
    client_t *cli,
    struct message *msg)
{
  int i;
  char params[MSGMAX];

  struct sendbuf *sb;
  sb = malloc(sizeof(*sb));
 
  if (!sb) {
    warn("Cannot allocate message for client send queue");
    goto fail;
  }

  /* Fill in the params string */
  memset(params, 0, MSGMAX);
  for (i=0; i < (msg->paramno-1); i++) {
    strncat(params, msg->params[i], MSGMAX);
    strncat(params, " ", 1);
  }
  if (msg->paramno > 0) {
    strncat(params, ":", MSGMAX);
    strncat(params, msg->params[msg->paramno-1], MSGMAX);
  }

  /* Create the appropriate message string */
  if (msg->prefix[0] == 0) {
    sb->len = snprintf(sb->msg, MSGMAX, "%s %s\r\n",
                        msg->command, params);
  }
  else {
    sb->len = snprintf(sb->msg, MSGMAX, ":%s %s %s\r\n", 
                        msg->prefix, msg->command, params);
  }

  /* Check and set the event mask if its the first message in the stack */
  if (cli->sbh.tqh_first == NULL) {
    /* This is not appropriate, need to get the event mask off of the queue */
    event_mod_event(cli->fd, (EPOLLIN | EPOLLOUT));
  }

  /* Insert the message onto the tail end of the queue */
  TAILQ_INSERT_TAIL(&cli->sbh, sb, tq);

  return 0;

fail:
  if (sb)
    free(sb);
  return -1;
}
