#ifndef CONFIG_H
#define CONFIG_H

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

enum verdict {
  NONE,      /* refers to a node not being initialized */
  DEFAULT,   /* what the calling programs default policy is */
  DROP,      /* Drop the packet */
  REJECT,    /* Reject the packet (currently unsupported?) */
  ALLOW,     /* Permit the packet */
  SPLIT,     /* When we must split the external node */
  DUPLICATE, /* The key inserted already exists as a higher priority */
  DETACHED,  /* The underlying database is being modified in some way that
                makes it inaccessible.
              */
  ERROR,     /* When an error happens */
};

#endif
