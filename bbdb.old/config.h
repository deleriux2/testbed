#ifndef CONFIG_H
#define CONFIG_H

#include <errno.h>
#include <string.h>

#define BBDB_WRITE 1

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

#endif
