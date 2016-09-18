#include "common.h"

extern struct config config;

static int container(
    void *data)
{
  V("Performing unshare");
  if (unshare(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWIPC|
              CLONE_NEWNET|CLONE_NEWUTS|CLONE_NEWUSER) < 0)
    err(EX_OSERR, "Cannot unshare");
  printf("moooo\n");
}

void create_container(
    void)
{
  pid_t pid;
  void *stack = NULL;
  struct rlimit stlim;

  V("Getting stack limit");
  if (getrlimit(RLIMIT_STACK, &stlim) < 0)
    err(EX_OSERR, "Couldn't get the stack limit");

  if (stlim.rlim_cur == RLIM_INFINITY)
    stlim.rlim_cur = 16*1024*1024;

  V("Allocating stack");
  if ((stack = malloc(stlim.rlim_cur)) == NULL)
    err(EX_OSERR, "Couldn't allocate memory for stack");

  V("Performing clone");
  if ((pid = clone(container, stack+stlim.rlim_cur, SIGCHLD, NULL)) < 0) {
    err(EX_OSERR, "Clone failed");
  }
}
