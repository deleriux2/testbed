#ifndef CONFIG_H
#define CONFIG_H
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <openssl/sha.h>

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <signal.h>

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>

#include <pthread.h>

#define WARN(args...) { \
    fprintf(stderr, "%s:%d:<%s>: %s: %s\n", \
    __FILE__, __LINE__, __FUNCTION__, args, strerror(errno)); \
  }

#define WARNX(args...) { \
    fprintf(stderr, "%s:%d:<%s>: %s\n", \
    __FILE__, __LINE__, __FUNCTION__, args); \
  }

#define ERR(exit_code, args...) { \
    fprintf(stderr, "%s:%d:<%s>: %s %s\n", \
    __FILE__, __LINE__, __FUNCTION__, args, strerror(errno)); \
    exit(EXIT_FAILURE); \
  }

#define ERRX(exit_code, args...) { \
    fprintf(stderr, "%s:%d:<%s>: %s\n", \
    __FILE__, __LINE__, __FUNCTION__, args); \
    exit(exit_code); \
  }

#define INFO(args...) WARNX(args...)
#define LOG(args...) WARNX(args...)

#define ATOMIC_INC(val) \
  __sync_fetch_and_add(&val, 1)

#define ATOMIC_DEC(val) \
  __sync_fetch_and_sub(&val, 1)

#define NONE  0
#define OPEN  1
#define CLOSE 2
#define SELF  3

enum verdict {
  DEFAULT,   /* what the calling programs default policy is */
  DROP,      /* Drop the packet */
  REJECT,    /* Reject the packet (currently unsupported?) */
  ALLOW,     /* Permit the packet */
  DUPLICATE, /* The key inserted already exists as a higher priority */
  NOTFOUND,  /* The entry is not found */
  DETACHED,  /* The underlying database is being modified in some way that
                makes it inaccessible. */
  SPLIT,     /* When we must split the external node */           
  REBALANCE, /* The external node requires rebalancing */
  DELETE,    /* The external node is empty and requires deleting */
  ERROR,     /* When an error happens */
};

#endif
