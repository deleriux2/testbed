#ifndef _COMMON_H
#define _COMMON_H
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#define _GNU_SOURCE

#define ON_ERR(errline, line) errno = 0; line; if (errno != 0) {\
		fprintf(stderr, "%s in %s from %s line %d: %s\n", errline, __func__,\
						__FILE__, __LINE__, strerror(errno));\
		exit(1);\
		}

#define ON_FAIL(errline, go, line) errno = 0; line;\
	if (errno != 0) { \
		fprintf(stderr, "%s in %s from %s line %d: %s\n", errline, __func__,\
						__FILE__, __LINE__, strerror(errno));\
		goto go;\
	}

/* Where a boolean procedure fails */
#define ON_FALSE(go, line) if (!(line)) { DEBUG_ERR(); goto go; }

#define SET_ERR(sess, maj, min, fail) {\
  if (sess->err_major == 0) { \
     sess->err_major = maj; \
     sess->err_minor = min; \
  }\
  goto fail; \
}
  

#define _LOG(level, ...) if (level >= log_level) \
	fprintf(stderr, __VA_ARGS__);

#define DEBUG_ERR() \
	fprintf(stderr, "Failure at %s from %s line %d\n", __func__,\
			__FILE__, __LINE__);\


enum ll {
	DEBUG,
	INFO,
	NOTICE,
	WARN,
	ERROR,
	CRITICAL,
	EMERGENCY
} log_level;

extern enum ll log_level;
#endif
