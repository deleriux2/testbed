#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "config.h"
#include "page.h"
#include "index.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

typedef struct crypto_page {
  uint16_t certificate_size;
  uint16_t signiture_size;
} crypto_page_t;
/* Certificate follows */
/* Signiture follows */

typedef struct crypto {
  pagemap_t *map;
  index_t *index;
  /* Which virtual page the offset lives in */
  uint64_t offset;
  bool pristine;
  X509 *root_certificate;
  X509 *certificate;
  EVP_PKEY *rsa_private_key;
  EVP_PKEY *rsa_public_key;
} crypto_t;


static inline uint8_t *get_certificate_page_buffer(
    crypto_page_t *cpage)
{
  assert(cpage);
  return (uint8_t *)cpage + sizeof(cpage);
}

crypto_t * crypto_new(pagemap_t *pagemap, index_t *index);
crypto_t * crypto_open(pagemap_t *pagemap, index_t *index);
void crypto_close(crypto_t *crypto);
int crypto_certificate_set(crypto_t *crypto, char *certpath);
int crypto_certificate_set_private_key(crypto_t *crypto, char *keypath);
int crypto_seal(crypto_t *crypto);
int crypto_verify(crypto_t *crypto);
#endif
