#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <assert.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "bbdb.h"

/* To add a new certificate do this:
 * 1. Create a new SSL certificate fully signed in DER format
 * 2. Run ld -r -b binary -o root.der.o [inputcrt_goes_here.der]
 * 3. Link the resulting root.der.o to the binary
 */

extern unsigned char _binary_root_der_start[];
extern unsigned int _binary_root_der_size;

static bbdb_ex_node_t * bbdb_external_node_init(bbdb_t *bbdb, int32_t upidx);
static inline bbdb_ex_node_t * bbdb_external(bbdb_t *bbdb, int pos);
static inline bbdb_in_node_t * bbdb_internal(bbdb_ex_node_t *ex, int pos);
static enum verdict bbdb_insert_internal(bbdb_ex_node_t *ex, bbdb_in_node_t *in, uint32_t key, enum verdict verdict, uint64_t left, uint64_t right);
static bbdb_in_node_t * bbdb_find_internal(bbdb_ex_node_t *ex, int key);
static bbdb_ex_node_t * bbdb_split(bbdb_t *bbdb, bbdb_ex_node_t *ex, uint32_t key);
static void * bbdb_pgindx_get_page(bbdb_t *bbdb, uint64_t pos);
static void bbdb_certificate_add(bbdb_t *bbdb, X509 *cert, X509_STORE *trustdb);
static void bbdb_signiture_add(bbdb_t *bbdb, EVP_PKEY *key);

