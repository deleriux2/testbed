#include "someirc.h"
#include "message.h"

/* Receive a pending message from the client */
/* WARNING: Non blocking sockets may not finish entire
 * message before succeeding. The message is considered
 * to be received when;
 *  a) Its last two chars are \r\n
 *  b) Its message buffer is full.
 */

static int client_recv(client_t *cli);
static int client_send(client_t *cli);

int client_sendrecv(
    int fd,
    int event,
    void *data)
{
  int rc;
  int rem, indx;
  client_t *cli = (client_t *)data;
  rem = MSGMAX - cli->msgbuf.index;

  if (event & (EPOLLERR|EPOLLHUP)) {
    /* Something went wrong, disconnect */
    warn("Client has gone away");
    return -1;
  }
  /* Send before we receive */
  else if (event & EPOLLOUT) {
    if (client_send(cli) < 0)
      return -1;
  }
  else if (event & EPOLLIN) {
    if (client_recv(cli) < 0) {
      return -1;
    }
  }
  else {
    warnx("Got an anomalous event from %s\n", cli->peername);
    return -1;    
  }

  return 0;
}

static int client_recv(
    client_t *cli)
{
  msg_t msg;
  int rc;
  memset(&msg, 0, sizeof(msg));

  /* Receive into our buffer */
  rc = recv(cli->fd, cli->msgbuf.msg + cli->msgbuf.index, 
                            MSGMAX - cli->msgbuf.index, 0);
  if (rc < 0) {
    warn("Error receiving from client");
    return -1;
  }
  else if (rc == 0) {
    warn("Client has gone away");
    return -1;
  }
  cli->msgbuf.index += rc;

  /* Determine if we are at the end of the string */
  if (cli->msgbuf.index >= MSGMAX) {
    message_parse(cli->msgbuf.msg, cli->msgbuf.index, &msg);
    memset(cli->msgbuf.msg, 0, MSGMAX);
    cli->msgbuf.index = 0;
  }
 
  if (cli->msgbuf.msg[cli->msgbuf.index-2] == '\r' &&
        cli->msgbuf.msg[cli->msgbuf.index-1] == '\n') {
    message_parse(cli->msgbuf.msg, cli->msgbuf.index, &msg);
    memset(cli->msgbuf.msg, 0, MSGMAX);
    cli->msgbuf.index = 0;
  }

  return 0;
}


/* Iterate through the send list, sending messages as we go */
static int client_send(
    client_t *cli)
{
  int rc;
  struct sendbuf *sb = cli->sbh.tqh_first;
  /* There is nothing in the send queue, dont epollout */
  if (!sb) {
    event_mod_event(cli->fd, EPOLLIN);
    return 0;
  }

  /* Send the buffer in the send queue */
  rc = send(cli->fd, sb->msg + sb->index, 
          sb->len - sb->index, MSG_NOSIGNAL);
  if (rc < 0) {
    warn("Unable to send data to client %s", cli->peername);
    return -1;
  }

  sb->index += rc;
  /* If this message finished sending, then remove entry from list */
  if (sb->index >= sb->len) {
    TAILQ_REMOVE(&cli->sbh, sb, tq);
    free(sb);
  }

  return 0;
}


/* Destroy client */
void client_destroy(void *data) {
  client_t *cli = (client_t *)data;

  if (!cli)
    return;

  event_del_fd(cli->fd);

  if (cli->fd > -1)
    close(cli->fd);

  free(cli);
  return;
}

