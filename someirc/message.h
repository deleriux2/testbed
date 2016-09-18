#ifndef _MESSAGE_H_
#define _MESSAGE_H_
#include "someirc.h"

#define MSGPARAM 15

/* Dont like this structure */
typedef struct message {
  char prefix[MSGMAX];
  char command[MSGMAX];
  char params[MSGPARAM][MSGMAX];
  int paramno;
} msg_t;

void message_init(void);
int message_push(client_t *cli, struct message *msg);
int message_parse(const char *str, int len, struct message *msg);
#endif

