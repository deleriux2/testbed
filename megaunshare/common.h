#ifndef _COMMON_H_
#define _COMMON_H_
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <err.h>
#include <sysexits.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <sched.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

#define V(str) \
   if (config.verbose) \
      printf("%s\n", str);

#define VF(fmt, args...) \
   if (config.verbose) \
      printf(fmt "\n", args);

struct config {
  char basedir[PATH_MAX];
  char command[PATH_MAX];
  char cmdargs;
  int verbose;
  uid_t uid;
  gid_t gid;
  unsigned int range;
};

void create_container(void);

#endif
