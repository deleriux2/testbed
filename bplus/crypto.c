#include "crypto.h"

extern unsigned char _binary_root_der_start[];
extern unsigned int _binary_root_der_size;

static int crypto_signiture_set(crypto_t *crypto, uint8_t *buffer, int sz);
static crypto_page_t * crypto_get_page(crypto_t *crypto);


static int crypto_signiture_get(
    crypto_t *crypto,
    uint8_t *buffer,
    int *sz)
{
  assert(crypto);
  assert(buffer);
  assert(sz);

  crypto_page_t *cpage;
  uint8_t *signiture_offset;
  int totalsz;
  cpage = crypto_get_page(crypto);
  if (!cpage)
    return 0;
  signiture_offset = (uint8_t *)cpage + sizeof(cpage) 
                              + cpage->certificate_size;

  /* Dont fetch it if its bigger than the page */
  totalsz = ((uint8_t *)(signiture_offset + cpage->signiture_size))
            - ((uint8_t *)cpage);
  if (totalsz > PAGESIZE)
    return 0;

  memcpy(buffer, signiture_offset, cpage->signiture_size);
  *sz = cpage->signiture_size;
  return 1;
}

/* Cryptographically validates database */
static int crypto_verify(
    crypto_t *crypto)
{
  assert(crypto);
  assert(crypto->rsa_public_key);

  page_t *page;

  bool found_license = false;
  int i, sz, rc = 0;
  int64_t records, page_offset;
  uint64_t magic;
  uint8_t license_checksum[SHA256_DIGEST_LENGTH];
  uint8_t *checksum;
  EVP_MD_CTX *evp;
  const EVP_MD *dgst;
  uint8_t signiture_buffer[PAGESIZE];

  memset(signiture_buffer, 0, PAGESIZE);

  /* If neither of these entries are found at least we verify with a 
   * known quantity.
   */
  memset(license_checksum, 0, SHA256_DIGEST_LENGTH);

  /* We dont share the other context here as its used for signing */
  dgst = EVP_sha256();
  evp = EVP_MD_CTX_create();
  if (!evp)
    goto end;

  records = crypto->index->record_num + crypto->index->size;

  if (!EVP_VerifyInit_ex(evp, dgst, NULL))
    goto end;

  for (i=0; i < records; i++) {
    page_offset = index_lookup(crypto->index, i);
    if (page_offset < 0)
      continue;

    page = page_get(crypto->map, page_offset);
    if (!page)
      goto end;

    checksum = page_get_checksum(page);
    magic = page_get_magic(page);

    if (magic == BBDB_MAGIC_EXNODE) {
      if (!EVP_VerifyUpdate(evp, checksum, SHA256_DIGEST_LENGTH))
        goto end;
      if (!page_validate_checksum(page))
        goto end;
    }
    else if (magic == BBDB_MAGIC_LICENSE) {
      found_license = true;
      memcpy(license_checksum, checksum, SHA256_DIGEST_LENGTH);
      if (!page_validate_checksum(page))
        goto end;
    }
  }

  if (found_license) {
    if (!EVP_VerifyUpdate(evp, license_checksum, SHA256_DIGEST_LENGTH))
      goto end;
  }

  /* Get current signiture */
  if (!crypto_signiture_get(crypto, signiture_buffer, &sz))
    goto end;

  /* Seal */
  rc = EVP_VerifyFinal(evp, signiture_buffer, sz, crypto->rsa_public_key);
  if (rc != 1)
    goto end;

  rc = 1;

end:
  pagemap_quiesce_pages(crypto->map);
  EVP_MD_CTX_destroy(evp);
  return rc;
}

static int validate_certificate(
    X509 *certificate,
    X509 *root_certificate)
{
  assert(certificate);
  assert(root_certificate);

  int rc = -1;
  X509_STORE *store;
  X509_STORE_CTX *ctx;

  ctx = X509_STORE_CTX_new();
  if (!ctx)
    goto end;
 
  store = X509_STORE_new();
  if (!store)
    goto end;

  if (!X509_STORE_add_cert(store, root_certificate))
    goto end;

  if (!X509_STORE_CTX_init(ctx, store, certificate, NULL))
    goto end;

  /* Verify */
  if (X509_verify_cert(ctx) != 1) {
    rc = 0;
    goto end;
  }
  rc = 1;

end:
  X509_STORE_CTX_cleanup(ctx);
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  return rc;
}

static int fetch_certificate_from_page(
  crypto_t *crypto,
  crypto_page_t *cpage)
{
  assert(crypto);
  assert(cpage);
  assert(cpage->certificate_size > 0);

  const uint8_t *buf;
  buf = get_certificate_page_buffer(cpage);

  crypto->certificate = 
    d2i_X509(NULL, &buf, (long int)cpage->certificate_size);
  if (!crypto->certificate)
    return 0;

  crypto->rsa_public_key = X509_get_pubkey(crypto->certificate);
  if (!crypto->rsa_public_key) {
    EVP_PKEY_free(crypto->rsa_public_key);
    return 0;
  }

  if (!validate_certificate(crypto->certificate, crypto->root_certificate))
    return 0;

  return 1;
}

static X509 * load_root_certificate(
    void)
{
  X509 *root_certificate;

  const uint64_t sz = (uint64_t)&_binary_root_der_size;
  const uint8_t *buf = _binary_root_der_start; 

  root_certificate = d2i_X509(NULL, &buf, sz);
  if (!root_certificate)
    return NULL;

  return root_certificate;
}

static int read_crypto_header(
    crypto_t *crypto)
{
  assert(crypto);
  assert(crypto->map);

  struct iovec vecs[1];
  int64_t pageno;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);

  if (preadv(crypto->map->fd, vecs, 1, CRYPTO_HDR_OFFSET) < 0)
    return 0;

  crypto->offset = pageno;
  return 1;
}

static int write_crypto_header(
    crypto_t *crypto)
{
  assert(crypto);
  assert(crypto->map);
  assert(crypto->offset >= 0);

  struct iovec vecs[1];

  int64_t pageno = crypto->offset;

  /* Assign vectors */
  vecs[0].iov_base = &pageno;
  vecs[0].iov_len = sizeof(pageno);

  if (pwritev(crypto->map->fd, vecs, 1, CRYPTO_HDR_OFFSET) < 0)
    return 0;

  return 1;
}

static crypto_page_t * crypto_get_page(
    crypto_t *crypto)
{
  assert(crypto);
  assert(crypto->map);

  crypto_page_t *cpage;
  int64_t offset;

  offset = index_lookup(crypto->index, crypto->offset);
  if (offset < 0)
    return NULL;

  cpage = page_get_data_of(crypto->map, offset, BBDB_MAGIC_CRYPTO);
  if (!cpage)
    return NULL;

  return cpage;
}

static int crypto_signiture_set(
    crypto_t *crypto,
    uint8_t *buffer,
    int sz)
{
  assert(crypto);
  assert(buffer);
  assert(sz > 0 && sz < PAGESIZE);

  crypto_page_t *cpage;
  uint8_t *signiture_offset;
  int totalsz;
  cpage = crypto_get_page(crypto);
  if (!cpage)
    return 0;
  signiture_offset = (uint8_t *)cpage + sizeof(cpage) 
                              + cpage->certificate_size;

  /* Dont write it if its bigger than the page */
  totalsz = ((uint8_t *)(signiture_offset + sz)) - ((uint8_t *)cpage);
  if (totalsz > PAGESIZE)
    return 0;

  cpage->signiture_size = sz;
  memcpy(signiture_offset, buffer, sz);
  return 1;
}

static int crypto_page_update_certificate(
    crypto_t *crypto,
    X509 *certificate)
{
  assert(crypto);
  assert(certificate);

  crypto_page_t *cpage;
  int sz;
  uint8_t *certificate_buffer;

  cpage = crypto_get_page(crypto);
  if (!cpage)
    return 0;

  certificate_buffer = get_certificate_page_buffer(cpage);
  sz = i2d_X509(certificate, &certificate_buffer);
  if (sz <= 0)
    return 0;

  cpage->certificate_size = (uint16_t)sz;
  
  if (cpage->signiture_size) {
    WARNX("Updating the certificate has clobbered the signiture."
          " It is now invalid!");
    cpage->signiture_size = 0;
  }
  return 1;  
}

static crypto_page_t * crypto_page_init(
    crypto_t *crypto)
{
  assert(crypto);
  assert(crypto->map);

  crypto_page_t *cpage;
  page_t *page;
  int offset;

  /* Assign page, add to index */
  page = page_init(crypto->map, BBDB_MAGIC_CRYPTO);
  offset = page_get_offset(crypto->map, page);

  if (!index_add(crypto->index, page))
    return NULL;

  cpage = page_get_data(page);

  cpage->certificate_size = 0;
  cpage->signiture_size = 0;

  crypto->offset = offset;

  return cpage; 
}


/* Creates a new crypto entry */
crypto_t * crypto_new(
    pagemap_t *map,
    index_t *index)
{
  assert(map);
  assert(index);

  crypto_t *crypto;

  crypto = malloc(sizeof(crypto_t));
  if (!crypto)
    return  NULL;

  crypto->map = map;
  crypto->index = index;

  crypto->root_certificate = load_root_certificate();
  crypto->certificate = NULL;
  crypto->rsa_private_key = NULL;
  crypto->rsa_public_key = NULL;
  crypto->pristine = true;

  if (!crypto->root_certificate)
    goto fail;

  if (!crypto_page_init(crypto))
    goto fail;

  return crypto;

fail:
  if (crypto) {
    if (crypto->root_certificate)
      X509_free(crypto->root_certificate);
    if (crypto->certificate)
      X509_free(crypto->certificate);
    if (crypto->rsa_public_key)
      EVP_PKEY_free(crypto->rsa_public_key);
    if (crypto->rsa_private_key)
      EVP_PKEY_free(crypto->rsa_private_key);
    if (!write_crypto_header(crypto))
      WARN("Cannot write the crypto header");
    free(crypto);
  }
}


crypto_t * crypto_open(
    pagemap_t *map,
    index_t *index)
{
  assert(map);
  assert(index);

  crypto_t *crypto;
  crypto_page_t *cpage;

  crypto = malloc(sizeof(crypto_t));
  if (!crypto)
    return  NULL;

  crypto->map = map;
  crypto->index = index;

  crypto->root_certificate = load_root_certificate();
  crypto->certificate = NULL;
  crypto->rsa_private_key = NULL;
  crypto->rsa_public_key = NULL;
  crypto->pristine = true;

  if (!read_crypto_header(crypto))
    goto fail;

  if (!crypto->root_certificate)
    goto fail;

  cpage = crypto_get_page(crypto);

  if (cpage->certificate_size)
    if (!fetch_certificate_from_page(crypto, cpage))
      crypto->pristine = false;
  if (cpage->signiture_size)
    if (!crypto_verify(crypto))
      crypto->pristine = false;

  return crypto;

fail:
  if (crypto) {
    if (crypto->root_certificate)
      X509_free(crypto->root_certificate);
    if (crypto->certificate)
      X509_free(crypto->certificate);
    if (crypto->rsa_public_key)
      EVP_PKEY_free(crypto->rsa_public_key);
    if (crypto->rsa_private_key)
      EVP_PKEY_free(crypto->rsa_private_key);
    if (!write_crypto_header(crypto))
      WARN("Cannot write the crypto header");
    free(crypto);
  }
  return NULL;
}


/* Loads, validates and pushes the certificate to the page */
int crypto_certificate_set(
    crypto_t *crypto,
    char *certpath)
{
  assert(crypto);
  assert(certpath);

  FILE *fd;
  X509 *certificate;
  EVP_PKEY *public_key;
  fd = fopen(certpath, "r");
  if (!fd)
    goto fail;

  /* Attempt a load as a PEM file, then as a DER file */
  certificate = PEM_read_X509(fd, NULL, NULL, NULL);
  if (!certificate) {
    fseek(fd, 0, 0);
    certificate = d2i_X509_fp(fd, &certificate);
    if (!certificate)
      goto fail;
  }
  public_key = X509_get_pubkey(certificate);
  if (!public_key)
    goto fail;

  if (!validate_certificate(certificate, crypto->root_certificate))
    goto fail;

  /* Place the certificate into the crypto page */
  if (!crypto_page_update_certificate(crypto, certificate))
    goto fail;

  /* Set certificate data in crypto */
  crypto->certificate = certificate;
  crypto->rsa_public_key = public_key;

  fclose(fd);
  return 1;
fail:
  if (fd)
    fclose(fd);
  if (certificate)
    X509_free(certificate);
  if (public_key)
    EVP_PKEY_free(public_key);
  return 0;
}


int crypto_certificate_set_private_key(
    crypto_t *crypto,
    char *keypath)
{
  assert(crypto);
  assert(keypath);

  FILE *fd;
  EVP_PKEY *private_key = NULL;

  fd = fopen(keypath, "r");

  if (!fd) {
    fclose(fd);
    return 0;
  }

  if (PEM_read_PrivateKey(fd, &private_key, NULL, NULL) == NULL) {
    fclose(fd);
    return 0;
  }

  crypto->rsa_private_key = private_key;

  fclose(fd);
  return 1;
}



/* Cryptographically seals database from further modification */
int crypto_seal(
    crypto_t *crypto)
{
  assert(crypto);
  assert(crypto->rsa_private_key);

  page_t *page;

  int i, sz, rc = 0;
  bool found_license = false;
  int64_t records, page_offset;
  uint64_t magic;
  uint8_t license_checksum[SHA256_DIGEST_LENGTH];
  uint8_t *checksum;
  EVP_MD_CTX *evp;
  const EVP_MD *dgst;
  uint8_t signiture_buffer[PAGESIZE];

  /* If neither of these entries are found at least we seal with a 
   * known quantity.
   */
  memset(license_checksum, 0, SHA256_DIGEST_LENGTH);

  /* We dont share the other context here as its used for signing */
  dgst = EVP_sha256();
  evp = EVP_MD_CTX_create();
  if (!evp)
    goto end;

  records = crypto->index->record_num + crypto->index->size;

  if (!EVP_SignInit_ex(evp, dgst, NULL))
    goto end;

  for (i=0; i < records; i++) {
    page_offset = index_lookup(crypto->index, i);
    /* Indicates that we hit a index page */
    if (page_offset < 0)
      continue;

    page = page_get(crypto->map, page_offset);
    if (!page)
      goto end;

    if (!page_set_checksum(page))
      goto end;

    checksum = page_get_checksum(page);
    magic = page_get_magic(page);

    if (magic == BBDB_MAGIC_EXNODE) {
      if (!EVP_SignUpdate(evp, checksum, SHA256_DIGEST_LENGTH))
        goto end;
    }
    else if (magic == BBDB_MAGIC_LICENSE) {
      found_license = true;
      memcpy(license_checksum, checksum, SHA256_DIGEST_LENGTH);
    }
  }

  /* Seal the tree first, then the license */
  if (found_license) {
    if (!EVP_SignUpdate(evp, license_checksum, SHA256_DIGEST_LENGTH))
      goto end;
  }

  /* Seal */
  if (!EVP_SignFinal(evp, signiture_buffer, &sz, crypto->rsa_private_key))
    goto end;

  if (!crypto_signiture_set(crypto, signiture_buffer, sz))
    goto end;

  rc = 1;

end:
  EVP_MD_CTX_destroy(evp);
  return rc;
}



/* Destroys entry */
void crypto_close(
    crypto_t *crypto)
{
  if (crypto) {
    if (crypto->root_certificate)
      X509_free(crypto->root_certificate);
    if (crypto->certificate)
      X509_free(crypto->certificate);
    if (crypto->rsa_public_key)
      EVP_PKEY_free(crypto->rsa_public_key);
    if (crypto->rsa_private_key)
      EVP_PKEY_free(crypto->rsa_private_key);
    if (!write_crypto_header(crypto))
      WARN("Cannot write the crypto header");
    free(crypto);
  }
}
