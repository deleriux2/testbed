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

#define VERSION "0.0.1"

#define ON_ERR(errline, line) errno = 0; line; if (errno != 0) {\
		fprintf(stderr, "%s in %s from %s line %d: %s\n", errline, __func__,\
						__FILE__, __LINE__, strerror(errno));\
		exit(1);\
		}
#endif
