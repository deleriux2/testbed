#ifndef _COMMON_H
#define _COMMON_H
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <pthread.h>
#include <netdb.h>
#include <fcntl.h>

#include <ev.h>

#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>

#define GNUTLS_CIPHER_PRIORITY "NONE:+AES-128-GCM:+ECDHE-RSA:+AEAD:+COMP-ALL:+VERS-TLS1.2:+SIGN-RSA-SHA256:+CURVE-ALL:+CTYPE-X509"
#define GNUTLS_BUNDLE_PATH "/etc/ssl/certs/ca-bundle.crt"

#define SHA256_KEY "CALL_ME_DADDY"
#define SHA256_KEYLEN 13

#define MAX_CONCURRENCY 100000
#endif
