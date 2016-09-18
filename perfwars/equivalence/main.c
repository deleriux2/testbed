#include "common.h"
#include "manager.h"
#include <limits.h>
#include <sys/resource.h>

gnutls_certificate_credentials_t cred = NULL;

struct {
  char *dbfile;
  char *hostname;
  char *port;
  int timeout;
} config = {
  "database.pws",
  "localhost",
  "8443",
  20,
};


static void init_libs(
    char *key,
    char *crt)
{
  gnutls_global_init();
  int rc;

  /* Load the Root CA list */
  rc = gnutls_certificate_allocate_credentials(&cred);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Initializing certificate list failed: %s\n", gnutls_strerror(rc));
  rc = gnutls_certificate_set_x509_trust_file(cred, GNUTLS_BUNDLE_PATH, GNUTLS_X509_FMT_PEM);
  if (rc == 0)
    errx(EXIT_FAILURE, "No root certificates found in: %s\n", GNUTLS_BUNDLE_PATH);
  else if (rc < 0)
    errx(EXIT_FAILURE, "Loading root certificates failed: %s: %s\n", GNUTLS_BUNDLE_PATH, gnutls_strerror(rc));

  rc = gnutls_certificate_set_x509_key_file(cred, crt, key, GNUTLS_X509_FMT_PEM);
  if (rc != GNUTLS_E_SUCCESS)
    errx(EXIT_FAILURE, "Initializing key / certificate failed: %s\n", gnutls_strerror(rc));
}

int main()
{
  int rc;
  manager_t *m;
  struct rlimit lim;

  /* Configure the concurrency setting */
  memset(&lim, 0, sizeof(lim));
  if (getrlimit(RLIMIT_NOFILE, &lim) < 0)
    err(EXIT_FAILURE, "Unable to acquire limits");

  lim.rlim_cur = lim.rlim_max; 
  if (setrlimit(RLIMIT_NOFILE, &lim) < 0)
    err(EXIT_FAILURE, "Cannot set max file limit");

  init_libs("/home/matthew/Testbed/perfwars/equivalence/localhost.key","/home/matthew/Testbed/perfwars/equivalence/localhost.crt");


  m = manager_init(config.dbfile, config.hostname, config.port, config.timeout);
  if(!m)
    exit(1);

  manager_run(m);
  printf("Started %d workers..\n", rc);
  sleep(3);
  manager_destroy(m);

  exit(0);
}
