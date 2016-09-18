#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <signal.h>

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <ev.h>

/* Basic details about this program */
#define PROGNAME "WafCheck"
#define VERSION  "0.80"
#define BUILD    "2015-07-25"
#define AUTHOR   "Matthew Ife"
#define EMAIL    "matthew.ife@firehost.com"

/* The ciphers we check for and against */
#define ACCEPTED_CIPHERS      "AES256-SHA256:AES256-SHA:AES128-SHA256:AES128-SHA:DES-CBC3-SHA"
#define REJECTED_CIPHERS      "-AES256-SHA256:-AES256-SHA:-AES128-SHA256:-AES128-SHA:-DES-CBC3-SHA"
#define PCI_ACCEPTED_CIPHERS  "AES:3DES:!AESGCM:!PSK:!KRB5:!ECDH:!DH"
#define PCI_REJECTED_CIPHERS  "-AES:-3DES:!ECDH:!DH:!PSK:!KRB5"

/* The paths that the program uses in its URLs */
#define WAFPATH "/cmd.exe"
#define STDPATH "/WafCheck"

/* What to look for during a waf test */
#define WAF_MATCHING_STRING "<title>FireHost Protection</title>"

/* Internal error codes */
#define MAJ_INTERNAL    0
#define MAJ_SYSTEM      1
#define MAJ_SSL         2

#define MIN_SUCCESS   0
#define MIN_SSL_ERROR 1
#define MIN_WAFCHECK  2

/* SSL Instance state codes */
#define STATE_INITIALIZED  0
#define STATE_STOPPED      1
#define STATE_STARTED      2
#define STATE_FINISHED     3

/* Config value definitions */
#define SSL3                1
#define TLS1                2
#define TLS1_1              4
#define TLS1_2              8
#define NO_VERBOSE          0
#define VERBOSE             1
#define WAF                 0
#define NO_WAF              1
#define PCI                 1
#define NO_PCI              0
#define CERT_VAL            1
#define NO_CERT_VAL         0
#define DEFAULT_PORT    "443"
#define DEFAULT_TIMEOUT   6.0

/* Various limits */
/* The greatest number of ciphers we expect ssl to spit out */
#define MAX_CIPHERS           512
/* The default concurrency used */
#define DEFAULT_CONCURRENCY   4
/* The highest concurrency you can select */
#define MAX_CONCURRENCY       10
/* The maximum timeout that can be set */
#define MAX_TIMEOUT           60.0
/* The maximum buffer used when sending/recieve in test */
#define SSL_INSTANCE_BUFSIZE  1048576
/* MAX_CONCURRENCY * SSL_INSTANCE_BUFSIZE memory usage */

/* Misc */
/* Error codes for SSL failure, stolen from OpenSSL */
#define SSL_NO_CIPHERS_AVAILABLE   0x140830B5
#define SSL_HANDSHAKE_FAILURE      0x14094410
#define SSL_PROTOCOL_VERSION       0x1409442e


/* Structures used in the program */

/* Each test lives in a structure like this */
typedef struct ssl_test {
  /* The protocol to select */
  const SSL_METHOD *ctx;
  /* The cipher to use */ 
  const char *cipher;
  /* Whether or not this tries to get a WAF block */
  int waf; 
  /* err_* contain the error received by the test */
  int err_maj;
  int err_min;
  /* fail_* contain the error expected to receive at test completion */
  int fail_maj;
  int fail_min;
} ssl_test;

/* Each tests runtime state it kept in an ssl_instance.
 *  * A pool of size MAX_CONCURRENCY is initialized at startup and 
 *   * as one test finishes, another is given the instance */
typedef struct ssl_instance {
  /* The socket and SSL instance */
  int fd;
  SSL *ssl;
  /* Can be initialized, stopped, started or finished */
  int state;
  /* The current test being ran */
  ssl_test *test;
  /* The event io entry */
  ev_io *io;
  /* The connection timeout timestamp */
  ev_tstamp timeout;
  /* Stores buffer of request/response */
  char *buffer;
  int buflen;
  int bufoffset;
} ssl_instance;

/* Stores default config values from arguments
 *  * passed by the user. */
struct config {
  /* The protocols we want to work on the WAF */
  int protocols;
  /* Whether or not to do a WAF check */
  int nowaf;
  /* Show results of all tests. */
  int verbose;
  /* Whether or not to do a PCI scan */
  int pci;
  /* The maximum concurrency given */
  int concurrency;
  /* Whether or not to do certificate validation */
  int certval;
  /* The hostname to query */
  char *hostname;
  /* The host header to use */
  char *host;
  /* The port to select */
  char *port;
  /* The timeout to use */
  double timeout;
  /* The resolved hostname */
  struct addrinfo *ai;
} config;

struct global_state {
  /* Used for initializing SSL connections */
  SSL_CTX *tls;
  /* Watcher used for inserting new tets */
  ev_idle idle;
  ev_timer timer;
  /* Our instance pool */
  ssl_instance* tls_instance_pool;
  /* Contains our tests */
  struct {
    ssl_test *tests;
    int testno;
    int testoff;
  } tests;
  /* The running number of connections active */
  int concurrency_level;
  /* Flag to indicate when the report has printed its header */
  int report_header;
  int success;
};

/* Function prototypes */
static inline int get_subject_names(X509 *cert, char (*sans)[256], int sz);
static inline void prepare_error_state(void);
static inline void print_usage(void);
static inline void print_help_bootstrap(void);
static inline void print_help(void);
static inline void print_info(void);
static inline void init_global_state(void);
static inline void set_test_err(ssl_test *test, int maj, int min);

static int get_ciphers(SSL *ssl, const char *cipherlist, const char **result);
static void add_more_tests(struct ev_loop *loop, ev_idle *idle, int events);
static void create_waf_tests(void);
static void init_openssl_library(void);
static void parse_config(int argc, char **argv);
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
static int wildcmp(const char *wild, const char *string);

static const char *ssl_instance_error_reason(ssl_instance *instance);
static void ssl_instance_print_report(ssl_instance *instance);
static void ssl_instance_reset(ssl_instance *instance);
static void ssl_instance_receive_response(struct ev_loop *loop, ev_io *io, int events);
static void ssl_instance_send_request(struct ev_loop *loop, ev_io *io, int events);
static void ssl_instance_ssl_connect(struct ev_loop *loop, ev_io *io, int events);
static void ssl_instance_check_connect(struct ev_loop *loop, ev_io *io, int events);

void ssl_instance_abort(ssl_instance *instance, int err_maj, int err_min);
void ssl_instance_set_callback(ssl_instance *instance, int event, void (*callback)(struct ev_loop *l, ev_io *i, int e));
void ssl_instance_disconnect(ssl_instance *instance);
ssl_instance * ssl_instance_create(int sz);
ssl_instance * ssl_instance_pool_initialize_test(ssl_instance *pool, int sz, ssl_test *test);

/* Global runtime state */
static struct global_state *g = NULL;

/* Initializes the global runtime */
static inline void init_global_state(
    void)
{
  sigset_t sigs;

  g = calloc(1, sizeof(struct global_state));
  g->success = 1;

  /* Block SIGPIPE */
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGPIPE);
  if (sigprocmask(SIG_BLOCK, &sigs, NULL) < 0)
    err(EXIT_FAILURE, "Cannot setup signals");
  return;
}

/* Clears error globals. */
static inline void prepare_error_state(
    void)
{
  ERR_clear_error();
  errno = 0;
}

static inline void set_test_err(
    ssl_test *test,
    int maj,
    int min)
{
  test->err_maj = maj;
  test->err_min = min;
}

static inline void ssl_instance_prepare_response(
    ssl_instance *instance)
{
  memset(instance->buffer, 0, SSL_INSTANCE_BUFSIZE);
  instance->buflen = SSL_INSTANCE_BUFSIZE;
  instance->bufoffset = 0;
}

/* Sets up the request buffer */
static inline void ssl_instance_prepare_request(
    ssl_instance *instance)
{
  const char *path;

  if (instance->test->waf)
    path = WAFPATH;
  else
    path = STDPATH;

  memset(instance->buffer, 0, SSL_INSTANCE_BUFSIZE);
  instance->bufoffset = 0;
  instance->buflen = snprintf(instance->buffer, SSL_INSTANCE_BUFSIZE, 
      "HTTP %s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Connection: close\r\n"
      "User-Agent: %s\r\n"
      "\r\n",
    path, config.host, PROGNAME" v"VERSION);
  return;
}

/* Prepares the SSL connection */
static inline void ssl_instance_prepare_ssl(
    ssl_instance *instance)
{
  /* Set the protocol and cipher */
  SSL_clear_options(instance->ssl, 0xFFFFFFFF);
  SSL_set_ssl_method(instance->ssl, instance->test->ctx);
  SSL_set_cipher_list(instance->ssl, instance->test->cipher);
  if (instance->test->ctx != SSLv3_client_method()) 
    SSL_set_tlsext_host_name(instance->ssl, config.host);
  SSL_set_fd(instance->ssl, instance->fd);
}

/* Returns all common names and DNSname SAN entries from certificate */
static inline int get_subject_names(
    X509 *cert,
    char (*sans)[256],
    int sz)
{
  int i;
  GENERAL_NAMES *names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  STACK_OF(CONF_VALUE) *vals = sk_CONF_VALUE_new_null();
  CONF_VALUE *conf;
  X509_NAME *subj = X509_get_subject_name(cert);

  /* Return the alt names */
  if (!names)
    return 0;
  if (!subj)
    return -1;

  /* This is utterly non-intuitive.. */
  i2v_GENERAL_NAMES(NULL, names, vals);
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

  for(i = 0; i < sk_CONF_VALUE_num(vals); i++) {
    conf = sk_CONF_VALUE_value(vals, i);
    if (strcmp(conf->name, "DNS") == 0)
      strncpy(sans[i], conf->value, 254);
    /* Should do IP addresses too, but not sure what the text string says */
  }
  sk_CONF_VALUE_free(vals);

  /* We had so many alt names we ran out of space! */
  if (i >= sz) {
    return -1;
  }

  /* Fetch the subject cn */
  if (X509_NAME_get_text_by_NID(subj, NID_commonName, sans[i], sizeof(sans[i])) <= 0)
    return -1;
  i++;

  return i;
}

static inline void print_usage(
    void)
{
  printf("Usage: wafcheck [OPTIONS] hostname\n");
}

static inline void print_help_bootstrap(
    void)
{
  printf("Use '--help' for more information.\n");
}

static inline void print_help(
    void)
{
  print_usage();
  printf(
"Check a domain name for compatibility with WAF.\n\n"
"OPTIONS\n"
"    --help                -h           Print this help\n"
"    --verbose             -v           Report result of every test, not just failed ones\n"
"    --info                -i           Print program info and exit\n"
"    --concurrency         -n NUMBER    Run NUMBER connections at once. Default: %d Max: %d\n"
"    --port                -p PORT      Use port PORT. Default: %s\n"
"    --timeout             -t NUMBER    Set timeout on each test in seconds. Default: %.0f Max: %.0f\n"
"    --host                -H HOSTNAME  Send a custom host header to the destination\n"
"    --ssl3                -S           Assume SSLv3 ciphers will work. Default: no\n"
"    --no-cert-validation  -C           Disable certificate validation.\n"
"    --no-tls1             -0           Assume TLSv1 ciphers will not work. Default: yes\n"
"    --tls1                             Assume TLSv1 ciperhs will work. Default: no\n"
"    --no-tls1_1           -1           Assume TLSv1.1 ciphers will not work. Default: no\n"
"    --tls1_1                           Assume TLSv1.1 ciphers will not work. Default: yes\n"
"    --no-tls1_2           -2           Assume TLSv1.2 ciphers will not work. Default: no\n"
"    --tls1_2                           Assume TLSv1.2 ciphers will work. Default: yes\n"
"    --no-waf              -W           Disable the waf check. Default: no\n"
"    --pci                 -P           Do a scan for PCI compliant ciphers and protocols instead\n"
"                                       implies --no-waf and --ssl3 is always disabled. Default: no\n"
"\n"
"All tests will be ran, disabling a protocol indicates to the program to test that\n"
"the server rejects communications via that protocol.\n"
"\n"
"Ciphers which should work, considered as 'accepted ciphers' must connect successfully\n"
"and demonstrate that the WAF protects the resource. All accepted ciphers are printed\n"
"in \e[1mbold\e[0m.\n"
"\n"
"Ciphers which should not work, known as 'rejected ciphers' must not accept the\n"
"connection. Acceptable failure can be because the protocol is switched off, or if\n"
"the cipher is rejected by the protocol.\n"
"\n"
"You can use the '--info' switch to get a list of currently accepted and rejected ciphers.\n"
"This result is representative only. Certain ciphers will never work on certain protocols\n"
"as they are incompatible. These ciphers are automatically de-selected.\n"
"\n"
"A connection may also fail because the certificate was invalid. You can switch this\n"
"off using '--no-cert-validation' or '-C'\n"
"\n"
"Altering the concurrency affects the speed of which the test will complete.\n"
"Be warned: setting this too high on a poor performing server may result in an\n"
"inaccurate test (as the server rejects the test for resource purposes) and possibly\n"
"can result in the server becoming unresponsive. As such, the maximum concurrency\n"
"permitted is 10.\n"
"\n"
"You can specify an IP address as the hostname and a custom host header with\n"
"the '-H' flag. This allows you to check servers not advertising said host\n"
"in DNS.\n"
"\n"
"All checks which succeed to hitting a URL will by default obtain the path \"%s\",\n"
"the resource does not need to exist on the remote site.\n"
"ciphers expected to work on the WAF will try to obtain the path \"%s\"\n"
"then look for the string \"%s\" to confirm\n"
"the WAF protected the link.\n"
"\n"
"You can disable the WAF check by passing the '--no-waf' flag\n"
"\n"
"Enabling the PCI scan will force SSL3 mode off and disable WAF checks.\n"
"It checks for the minimum acceptable ciphers to pass a PCI scan.\n"
"This check disables TLS1 by default, enable it again with --tls1.\n"
"\n\n", DEFAULT_CONCURRENCY, MAX_CONCURRENCY, DEFAULT_PORT, DEFAULT_TIMEOUT,
MAX_TIMEOUT, STDPATH, WAFPATH, WAF_MATCHING_STRING);
}

static inline void print_info(
    void)
{
  printf("%s v%s Build Date: %s\nWritten by %s (%s)\n",
         PROGNAME, VERSION, BUILD, AUTHOR, EMAIL);
  printf("\n");
  printf("\e[1m\e[37mAccepted ciphers\e[0m: \e[1m\e[37m%s\e[0m\n", ACCEPTED_CIPHERS);
  printf("Rejected ciphers: %s\n", REJECTED_CIPHERS);
  printf("\n");
  printf("\e[1m\e[37mPCI compliant accepted ciphers\e[0m: \e[1m\e[37m%s\e[0m\n", PCI_ACCEPTED_CIPHERS);
  printf("PCI compliant rejected ciphers: %s\n", PCI_REJECTED_CIPHERS);
}

/* Sets up the openssl library for runtime */
static void init_openssl_library(
    void)
{
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_crypto_strings();
  OPENSSL_config(NULL);

  const SSL_METHOD *m1 = TLSv1_client_method();
  if (!m1)
    goto fail;

  g->tls = SSL_CTX_new(m1);
  if (!g->tls)
    goto fail;
  SSL_CTX_set_verify(g->tls, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_default_verify_paths(g->tls);

  return;

fail:
   errx(EXIT_FAILURE, "Error initializing library: %s", ERR_reason_error_string(ERR_get_error())); 
}

/* Returns list of individual ciphers from a cipherlist */
static int get_ciphers(
    SSL *ssl,
    const char *cipherlist,
    const char **result)
{
  const char *p;
  int sz=0;

  if (SSL_set_cipher_list(ssl, cipherlist) == 0)
    return 0;

  while ((p = SSL_get_cipher_list(ssl, sz)) != NULL) {
    result[sz] = p;
    sz++;
  }

  return sz;
}

/* Creates all the WAF tests */
static void create_waf_tests(
    void)
{

  SSL *tmpssl = NULL;
  ssl_test *tests;
  const char *ciphers[MAX_CIPHERS];
  int sz;
  int i,j;
  int testno = 0;
  int waf = 1;

  const unsigned long tls_vers[] = {
    TLS1, TLS1_1, TLS1_2, 0
  };
  const SSL_METHOD *tls_methods[] = {
    TLSv1_client_method(),
    TLSv1_1_client_method(),
    TLSv1_2_client_method(),
    NULL
  };

  const char SSL_ACCEPTED_CIPHERS[] = ACCEPTED_CIPHERS ":-TLSv1.2:-TLSv1";
  const char *TLS_ACCEPTED_CIPHERS[] = { 
    ACCEPTED_CIPHERS ":-TLSv1.2",
    ACCEPTED_CIPHERS ":-TLSv1.2",
    ACCEPTED_CIPHERS,
    NULL
  };
  const char SSL_REJECTED_CIPHERS[] = "SSLv3:"REJECTED_CIPHERS;
  const char *TLS_REJECTED_CIPHERS[] = {
    "TLSv1:SSLv3:"REJECTED_CIPHERS,
    "TLSv1:SSLv3:"REJECTED_CIPHERS,
    "TLSv1.2:TLSv1:SSLv3:"REJECTED_CIPHERS,
    NULL
  };

  const char *SSL_ALL = "SSLv3";
  const char *TLS_ALL[] = {
    "SSLv3:TLSv1", "SSLv3:TLSv1", "SSLv3:TLSv1:TLSv1.2",
  };

  /* If in pci mode, switch out the ciphers */
  if (config.pci == PCI) {
    TLS_ACCEPTED_CIPHERS[0] = PCI_ACCEPTED_CIPHERS ":-TLSv1.2";
    TLS_ACCEPTED_CIPHERS[1] = PCI_ACCEPTED_CIPHERS ":-TLSv1.2";
    TLS_ACCEPTED_CIPHERS[2] = PCI_ACCEPTED_CIPHERS;

    TLS_REJECTED_CIPHERS[0] = "TLSv1:SSLv3:" PCI_REJECTED_CIPHERS;
    TLS_REJECTED_CIPHERS[1] = "TLSv1:SSLv3:" PCI_REJECTED_CIPHERS;
    TLS_REJECTED_CIPHERS[2] = "TLSv1.2:TLSv1:SSLv3:" PCI_REJECTED_CIPHERS;
  }

  /* Initially allocate a huge number for the tests, lower it later */
  tests = calloc(MAX_CIPHERS * 8, sizeof(ssl_test));
  if (!tests)
    err(EXIT_FAILURE, "Cannot allocate memory for test");

  /* SSL3 is first */
  tmpssl = SSL_new(g->tls);
  SSL_set_ssl_method(tmpssl, SSLv3_client_method());
  if (!tmpssl)
    goto fail;

  /* Perform waf checks on SSL3 connections */
  if ((config.protocols & SSL3) == SSL3) {
    /* Generate test for accepted ciphers first */
    sz = get_ciphers(tmpssl, SSL_ACCEPTED_CIPHERS, ciphers);

    for (i=0; i < sz; i++) {
      /* Expect accepted ciphers to work, we do a non-waf check */
      tests[testno].ctx = SSLv3_client_method();
      tests[testno].cipher = ciphers[i];
      tests[testno].waf = 0;
      tests[testno].fail_maj = MAJ_INTERNAL;
      tests[testno].fail_min = MIN_SUCCESS;
      testno++;
    }

    for (i=0; i < sz; i++) {
      if (config.nowaf == WAF) {
        /* Expect accepted ciphers to work. We do a waf check */
        tests[testno].ctx = SSLv3_client_method(); 
        tests[testno].cipher = ciphers[i];
        tests[testno].waf = 1;
        tests[testno].fail_maj = MAJ_INTERNAL;
        tests[testno].fail_min = MIN_SUCCESS;
        testno++;
      }
    }

    /* Generate test for rejected ciphers next */
    sz = get_ciphers(tmpssl, SSL_REJECTED_CIPHERS, ciphers);

    for (i=0; i < sz; i++) {
      /* Expect rejected ciphers to fail, we do a non-waf check */
      tests[testno].ctx = SSLv3_client_method(); 
      tests[testno].cipher = ciphers[i];
      tests[testno].waf = 0;
      tests[testno].fail_maj = MAJ_INTERNAL;
      tests[testno].fail_min = MIN_SSL_ERROR;
      testno++;
    }

  }
  /* No option asked for SSL3, do reject tests on all */
  else {
    sz = get_ciphers(tmpssl, SSL_ALL, ciphers);

    for (i=0; i < sz; i++) {
      /* Expect rejected ciphers to fail, we do a non-waf check */
      tests[testno].ctx = SSLv3_client_method();
      tests[testno].cipher = ciphers[i];
      tests[testno].waf = 0;
      tests[testno].fail_maj = MAJ_INTERNAL;
      tests[testno].fail_min = MIN_SSL_ERROR;
      testno++;
    }
  }

  SSL_free(tmpssl);

  /* Now the TLS tests */
  for (j=0; tls_vers[j] != 0; j++) {
    tmpssl = SSL_new(g->tls);
    if (!tmpssl)
      goto fail;
    SSL_set_ssl_method(tmpssl, tls_methods[j]);

    if ((config.protocols & tls_vers[j]) == tls_vers[j]) {
      /* Generate test for accepted ciphers first */
      sz = get_ciphers(tmpssl, TLS_ACCEPTED_CIPHERS[j], ciphers);

      for (i=0; i < sz; i++) {
        /* Expect accepted ciphers to work, we do a non-waf check */
        tests[testno].ctx = tls_methods[j];
        tests[testno].cipher = ciphers[i];
        tests[testno].waf = 0;
        tests[testno].fail_maj = MAJ_INTERNAL;
        tests[testno].fail_min = MIN_SUCCESS;
        testno++;
      }

      for (i=0; i < sz; i++) {
        if (config.nowaf == WAF) {
          /* Expect accepted ciphers to work. We do a waf check */
          tests[testno].ctx = tls_methods[j];
          tests[testno].cipher = ciphers[i];
          tests[testno].waf = 1;
          tests[testno].fail_maj = MAJ_INTERNAL;
          tests[testno].fail_min = MIN_SUCCESS;
          testno++;
        }
      }

      /* Generate test for rejected ciphers next */
      sz = get_ciphers(tmpssl, TLS_REJECTED_CIPHERS[j], ciphers);

      for (i=0; i < sz; i++) {
        /* Expect rejected ciphers to fail, we do a non-waf check */
        tests[testno].ctx = tls_methods[j];
        tests[testno].cipher = ciphers[i];
        tests[testno].waf = 0;
        tests[testno].fail_maj = MAJ_INTERNAL;
        tests[testno].fail_min = MIN_SSL_ERROR;
        testno++;
      }
    }

    /* No option set for this protocol. Expect all to fail */
    else {
      sz = get_ciphers(tmpssl, TLS_ALL[j], ciphers);
  
      for (i=0; i < sz; i++) {
        tests[testno].ctx = tls_methods[j];
        tests[testno].cipher = ciphers[i];
        tests[testno].waf = 0;
        tests[testno].fail_maj = MAJ_INTERNAL;
        tests[testno].fail_min = MIN_SSL_ERROR;
        testno++;
      }

    }
    SSL_free(tmpssl);
  }

  /* Reallocate test size and set in global state */
  g->tests.tests = realloc(tests, sizeof(*tests) * testno);
  g->tests.testno = testno;

  return;

fail:
  errx(EXIT_FAILURE, "Error initializing tests: %s", ERR_reason_error_string(ERR_get_error()));
}

/* Performs additional certificate verification */
int verify_callback(
    int preverify_ok,
    X509_STORE_CTX *ctx)
{
  int depth = X509_STORE_CTX_get_error_depth(ctx);
  int i;
  int total = 0;
  int matched = 0;
  X509 *cert = NULL;
  char dnsnames[MAX_CIPHERS][256];

  memset(dnsnames, 0, sizeof(*dnsnames) * MAX_CIPHERS);

  /* If preverify fails, fail here too */
  if (!preverify_ok)
    return 0;

  /* Ignore root certs, preverify checks that */
  if (depth > 0)
    return preverify_ok;

  cert = X509_STORE_CTX_get_current_cert(ctx);

  /* Try to get the subject alt names */
  total = get_subject_names(cert, dnsnames, MAX_CIPHERS);
  for (i=0; i < total; i++) {
    if (wildcmp(dnsnames[i], config.host)) {
      matched = 1;
      break;
    }
  }
  if (!matched)
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);

  return matched;
}

/* Helper function compares strings */
/* Nabbed from http://www.emoticode.net/c/simple-wildcard-string-compare-globbing-function.html */
static int wildcmp(
    const char *wild,
    const char *string)
{
  const char *cp = NULL, *mp = NULL;

  while ((*string) && (*wild != '*')) {
     if ((*wild != *string) && (*wild != '?')) {
      return 0;
    }
    wild++;
    string++;
  }

  while (*string) {
    if (*wild == '*') {
      if (!*++wild) {
        return 1;
      }
      mp = wild;
      cp = string+1;
    }
    else if ((*wild == *string) || (*wild == '?')) {
      wild++;
      string++;
    }
    else {
      wild = mp;
      string = cp++;
    }
  }

  while (*wild == '*') {
    wild++;
  }
  return !*wild;
}

/* Creates an instance 'pool' which the event queue works with */
ssl_instance * ssl_instance_create(int sz)
{
  assert(sz > 0);
 
  int i;
  struct ssl_instance *instances = NULL;

  instances = calloc(sz, sizeof(ssl_instance));
  if (!instances)
    err(EXIT_FAILURE, "Cannot create instance pool");

  for (i=0; i < sz; i++) {
    instances[i].fd = -1;

    /* The method used here is pretty redundant, its just to get something initialized */
    instances[i].ssl = SSL_new(g->tls);

    if (!instances[i].ssl)
      errx(EXIT_FAILURE, "Error initializing SSL instance: %s", ERR_reason_error_string(ERR_get_error()));

    instances[i].state = STATE_INITIALIZED;
    instances[i].io = malloc(sizeof(ev_io));
    ev_init(instances[i].io, NULL);
 
    if (instances[i].io == NULL)
      err(EXIT_FAILURE, "Error initializing SSL instance");

    instances[i].test = NULL;
    instances[i].buffer = calloc(SSL_INSTANCE_BUFSIZE, 1);
    if (!instances[i].buffer)
      err(EXIT_FAILURE, "Error allocating memory for SSL instance");
  }

  return instances;
}

/* Assigns callback to ssl instance, adds to event loop if not already present and assigns event to watch for */
void ssl_instance_set_callback(
    ssl_instance *instance,
    int event,
    void (*callback)(struct ev_loop *l, ev_io *i, int e))
{
  assert(instance);

  /* If the callback is null, remove from the event queue */
  /* NOTE actually shutting down / clearing a connection is NOT done from here! */
  if (callback == NULL) {
    ev_io_stop(EV_DEFAULT, instance->io);
    instance->io->data = NULL;
    instance->state = STATE_STOPPED;
  }

  /* We are setting a callback */
  else {
    /* If a callback already exists, stop io. Then set callback and start io */
    if (ev_cb(instance->io) != NULL)
      ev_io_stop(EV_DEFAULT, instance->io);

    ev_set_cb(instance->io, callback);
    ev_io_set(instance->io, instance->fd, event);
    ev_io_start(EV_DEFAULT, instance->io);
    instance->io->data = instance;
    /* Re-arm timer */
    instance->timeout = ev_now(EV_DEFAULT);
  }
  instance->state = STATE_STARTED;
}

/* Disconnect from remote source */
void ssl_instance_disconnect(
    ssl_instance *instance)
{
  ssl_instance_set_callback(instance, 0, NULL);
  SSL_shutdown(instance->ssl);
  close(instance->fd);
  instance->state = STATE_FINISHED;
  instance->fd = -1;
}

/* Produces a human readable reason for an error */
static const char *ssl_instance_error_reason(
    ssl_instance *instance)
{
  int emin = instance->test->err_min;
  int emax = instance->test->err_maj;

  /* Errors are all lower case because openssl library uses all */
  /* lower case too.. keeps the format standardised */
  switch (emax) {
  case MAJ_INTERNAL:
    switch (emin) {

    case MIN_SUCCESS:
      return "ssl connection was completed successfully";
    break;

    case MIN_SSL_ERROR:
      return ERR_reason_error_string(ERR_get_error());
    break; 

    case MIN_WAFCHECK:
      return "waf did not protect url";
    break;

    default:
      return "unknown internal error. this is a bug";
    break;
    }
  break;

  case MAJ_SYSTEM:
    return strerror(emin);
  break;

  case MAJ_SSL:
    return ERR_reason_error_string(emin);
  break;

  default:
    return "unknown internal major error. this is a bug";
  break;
  }
}

/* Runs the report of the connection */
static void ssl_instance_print_report(
    ssl_instance *instance)
{
  struct ssl_test *test = instance->test;
  char buf[1024];
  char cipher[96];
  char *p = buf;
  int pass = 0;
  memset(buf, 0, 1024); 

  /* Make the cipher bold if its an accepted cipher */
  if (test->fail_maj == MAJ_INTERNAL && test->fail_min == MIN_SUCCESS)
    snprintf(cipher, 96, "\e[1m\e[37m%-30s\e[0m", test->cipher);
  else
    snprintf(cipher, 96, "%-30s", test->cipher);
  
  if (test->ctx == SSLv3_client_method())
    p += snprintf(p, 512, "%-10s%-30s", "SSLv3", cipher);
  else if (test->ctx == TLSv1_client_method()) 
    p += snprintf(p, 512, "%-10s%-30s", "TLSv1.0", cipher);
  else if (test->ctx ==  TLSv1_1_client_method())
    p += snprintf(p, 512, "%-10s%-30s", "TLSv1.1", cipher);
  else if (test->ctx == TLSv1_2_client_method())
    p += snprintf(p, 512, "%-10s%-30s", "TLSv1.2", cipher);
  
  if (test->waf == 0 && test->err_maj == test->fail_maj && test->err_min == test->fail_min) {
    p += snprintf(p, 512, "%20s%1s", "\e[40m\e[32m\e[1mPASSED\e[0m", "");
    pass = 1;
  }
  else if (test->err_maj != test->fail_maj || test->err_min != test->fail_min) {
    p += snprintf(p, 512, "%20s%1s", "\e[40m\e[31m\e[1mFAILED\e[0m", "");
    g->success = 0;
  }
  /* If its a successful test with additional WAF test flagged */
  else if (test->waf == 1 && test->err_maj == test->fail_maj && test->err_min == test->fail_min) {
    /* Look for WAF_MATCHING_STRING in the response */
    if (strstr(instance->buffer, WAF_MATCHING_STRING)) {
      p += snprintf(p, 512, "%20s%1s", "\e[40m\e[32m\e[1mPASSED\e[0m", "");
      pass = 1;
    }
    else {
      p += snprintf(p, 512, "%20s%1s", "\e[40m\e[31m\e[1mFAILED\e[0m","");
      test->err_maj = MAJ_INTERNAL; test->err_min = MIN_WAFCHECK;
      g->success = 0;
    }
  }

  /* Generally - avoid printing passing tests, just the failed ones */
  /* If verbose mode on then go ahead and just do everything anyway */
  if (!pass || config.verbose) {
    p += snprintf(p, 512, "%-50s", ssl_instance_error_reason(instance)); 
    if (!g->report_header) {
      g->report_header = 1;
      printf("%-10s%-30s%-6s%1s%-50s\n", "Protocol", "Cipher", "Result", "", "Reason");
    }
    printf("%s\n", buf);
  }
}

/* Resetting the instance allows it to be reused by the pool */
static void ssl_instance_reset(
  ssl_instance *instance)
{
  if (instance->state != STATE_FINISHED)
    return;

  ssl_instance_print_report(instance);

  instance->state = STATE_INITIALIZED;
  instance->timeout = 0;
  ev_init(instance->io, NULL);
  instance->fd = -1;
  instance->test = NULL;
  SSL_free(instance->ssl);
  instance->ssl = SSL_new(g->tls);
  g->concurrency_level--;
  /* Signal idle handler to put more tests in from the queue */
  ev_idle_start(EV_DEFAULT, &g->idle);

  prepare_error_state();
}

/* Aborts/resets a connection */
void ssl_instance_abort(
    ssl_instance *instance,
    int err_maj,
    int err_min)
{
  /* Set error */
  set_test_err(instance->test, err_maj, err_min);
  /* Unregister from event queue and clear callback */
  ssl_instance_set_callback(instance, 0, NULL);
  /* Disconnect and reset */
  ssl_instance_disconnect(instance);
  ssl_instance_reset(instance);
}

/* Instance callback states */
/* States pass through the following order
 * ssl_instance_pool_initialize_test (connect starts here) *
 * ssl_instance_pool_check_connect *
 * ssl_instance_ssl_connect *
 * ssl_instance_send_request *
 * ssl_instance_receive_response *
 */


/* Receive response */
static void ssl_instance_receive_response(
    struct ev_loop *loop,
    ev_io *io,
    int events)
{
  int sz, err;
  struct ssl_instance *instance = io->data;

  prepare_error_state();

  sz = SSL_read(instance->ssl, instance->buffer + instance->bufoffset, instance->buflen - instance->bufoffset);
  if (sz == 0) {
    err = SSL_get_error(instance->ssl, sz);
    if (err == SSL_ERROR_ZERO_RETURN || SSL_get_shutdown(instance->ssl) == SSL_RECEIVED_SHUTDOWN) {
      instance->buflen = instance->bufoffset;
      set_test_err(instance->test, MAJ_INTERNAL, MIN_SUCCESS);
      ssl_instance_disconnect(instance);
      ssl_instance_reset(instance);
    } 
    else if (err == 0) {
      err = ERR_get_error();
      instance->buflen = instance->bufoffset;
      set_test_err(instance->test, MAJ_INTERNAL, MIN_SUCCESS);
      ssl_instance_disconnect(instance);
      ssl_instance_reset(instance);
    }
    else if (err == SSL_ERROR_WANT_READ) {
      ssl_instance_set_callback(instance, EV_READ, ssl_instance_receive_response);
    }
    else if (err == SSL_ERROR_WANT_WRITE) {
      ssl_instance_set_callback(instance, EV_WRITE, ssl_instance_receive_response);
    }
    else if (err == SSL_ERROR_SSL) {
      err = ERR_get_error();
      ssl_instance_abort(instance, MAJ_SSL, err);
    }
    else if (err == SSL_ERROR_SYSCALL) {
      if (errno == 0) {
        /* Sometimes peer closes quicker than we have a chance to check */
        instance->buflen = instance->bufoffset;
        set_test_err(instance->test, MAJ_INTERNAL, MIN_SUCCESS);
        ssl_instance_disconnect(instance);
        ssl_instance_reset(instance);
      }
      else {
        err = ERR_get_error();
        ssl_instance_abort(instance, MAJ_SSL, err);
      }
    }
  }
  else if (sz < 0) {
    err = SSL_get_error(instance->ssl, sz);
    if (err == SSL_ERROR_WANT_READ) {
      ssl_instance_set_callback(instance, EV_READ, ssl_instance_receive_response);
      return;
    }
    else if (err == SSL_ERROR_WANT_WRITE) {
      ssl_instance_set_callback(instance, EV_WRITE, ssl_instance_receive_response);
      return;
    }
    
    err = ERR_get_error();
    ssl_instance_abort(instance, MAJ_SSL, err);
  }
  else {
    instance->bufoffset += sz;
  }
}

/* Sends the request */
static void ssl_instance_send_request(
    struct ev_loop *loop,
    ev_io *io,
    int events)
{
  struct ssl_instance *instance = io->data;
  int sz = 0;
  int err;

  prepare_error_state();

  sz = SSL_write(instance->ssl, instance->buffer + instance->bufoffset, instance->buflen - instance->bufoffset);
  if (sz == 0) {
    /* Check to see if we disconnected or something else */
    err = SSL_get_error(instance->ssl, sz);
    if (err == SSL_ERROR_ZERO_RETURN)
      ssl_instance_abort(instance, MAJ_SYSTEM, ECONNRESET);
  }
  else if (sz < 0) {
    err = SSL_get_error(instance->ssl, sz);
    if (err == SSL_ERROR_WANT_WRITE) {
      ssl_instance_set_callback(instance, EV_WRITE, ssl_instance_send_request);
      return;
    }
    else if (err == SSL_ERROR_WANT_READ) {
      ssl_instance_set_callback(instance, EV_READ, ssl_instance_send_request);
      return;
    }
    ssl_instance_abort(instance, MAJ_SSL, err);
  }
  else {
    instance->bufoffset += sz;
    if (instance->bufoffset >= instance->buflen) {
      ssl_instance_prepare_response(instance);
      ssl_instance_set_callback(instance, EV_READ, ssl_instance_receive_response);
    }
  }
}

/* Negotiate SSL connection */
static void ssl_instance_ssl_connect(
    struct ev_loop *loop,
    ev_io *io,
    int events)
{
  struct ssl_instance *instance = io->data;
  int err = 0, rc;

  prepare_error_state();

  rc = SSL_connect(instance->ssl);
  if (rc == 1) {
    /* Success */
    ssl_instance_prepare_request(instance);
    ssl_instance_set_callback(instance, EV_WRITE, ssl_instance_send_request);
  }
  else if (rc < 0) {
    /* Can mean negotiation not yet finished */
    err = SSL_get_error(instance->ssl, rc);
    if (err == SSL_ERROR_WANT_READ) {
      ssl_instance_set_callback(instance, EV_READ, ssl_instance_ssl_connect);
    }
    else if (err == SSL_ERROR_WANT_WRITE) {
      ssl_instance_set_callback(instance, EV_WRITE, ssl_instance_ssl_connect);
    }
    else {
      err = SSL_get_error(instance->ssl, rc);
      if (err == SSL_ERROR_SSL) {
        err = ERR_peek_error();
        if (err == SSL_NO_CIPHERS_AVAILABLE || err == SSL_HANDSHAKE_FAILURE ||
            err == SSL_PROTOCOL_VERSION)
          ssl_instance_abort(instance, MAJ_INTERNAL, MIN_SSL_ERROR);
        else 
          ssl_instance_abort(instance, MAJ_SSL, err);
      }
    }
  }
  else if (rc == 0) {
    err = SSL_get_error(instance->ssl, rc);
    if (err == SSL_ERROR_ZERO_RETURN || SSL_get_shutdown(instance->ssl) == SSL_RECEIVED_SHUTDOWN) {
      set_test_err(instance->test, MAJ_INTERNAL, MIN_SSL_ERROR);
      ssl_instance_disconnect(instance);
      ssl_instance_reset(instance);
    }
    else if (err == 0) {
      err = ERR_get_error();
      instance->buflen = instance->bufoffset;
      set_test_err(instance->test, MAJ_INTERNAL, MIN_SSL_ERROR);
      ssl_instance_disconnect(instance);
      ssl_instance_reset(instance);
    }
    else if (err == SSL_ERROR_SSL) {
      err = ERR_peek_error();
      if (err == SSL_NO_CIPHERS_AVAILABLE || err == SSL_HANDSHAKE_FAILURE ||
          err == SSL_PROTOCOL_VERSION)
        ssl_instance_abort(instance, MAJ_INTERNAL, MIN_SSL_ERROR);
      else
        ssl_instance_abort(instance, MAJ_SSL, err);
    }
    else if (err == SSL_ERROR_SYSCALL) {
      if (errno == 0) {
        /* Microsoft servers appear to just drop the connection in the event it doesn't like protocol */
        /* Force a 'pass' for the test. Dirty hack, I should be ashamed of myself. */
        set_test_err(instance->test, MAJ_SSL, SSL_HANDSHAKE_FAILURE);
        instance->test->fail_maj = MAJ_SSL; 
        instance->test->fail_min = SSL_HANDSHAKE_FAILURE;
        ssl_instance_disconnect(instance);
        ssl_instance_reset(instance);
      }
      else {
        err = ERR_get_error();
        ssl_instance_abort(instance, MAJ_SYSTEM, errno);
      }
    }
  }
}

/* Checks connection state of connecting socket */
static void ssl_instance_check_connect(
    struct ev_loop *loop,
    ev_io *io,
    int events)
{
  int rc, err;
  rc = sizeof(err);
  ssl_instance *instance = io->data;

  prepare_error_state();

  /* Check the error status */
  if (getsockopt(instance->fd, SOL_SOCKET, SO_ERROR, &err, (socklen_t *)&rc) < 0) {
    ssl_instance_abort(instance, MAJ_SYSTEM, errno);
    return;
  }

  if (err != 0) {
    ssl_instance_abort(instance, MAJ_SYSTEM, err);
    return;
  }
  ssl_instance_prepare_ssl(instance);
  ssl_instance_set_callback(instance, EV_WRITE, ssl_instance_ssl_connect);
}

/* Selects a free instance, if one available - and sets up the test */
/* for the event queue */
ssl_instance * ssl_instance_pool_initialize_test(
    ssl_instance *pool,
    int sz,
    ssl_test *test)
{
  assert(pool);
  assert(test);
  assert(sz > 0);

  prepare_error_state();

  int i;
  ssl_instance *next = NULL;
  /* Find the next available instance in the pool by checking the state */
  for (i=0; i < sz; i++) {
    if (pool[i].state == STATE_INITIALIZED) {
      next = &pool[i];
      break;
    }
  }
  /* There are no more instances available */
  if (!next)
    goto fail;

  /* Already at highest concurrency */
  if (g->concurrency_level >= config.concurrency)
    goto fail;
  g->concurrency_level++;

  /* Assign the test and initialize key data */
  next->state = STATE_INITIALIZED;
  next->test = test;
  next->timeout = 0;
  ev_init(next->io, NULL);
  next->fd = socket(config.ai->ai_family, config.ai->ai_socktype|SOCK_NONBLOCK, config.ai->ai_protocol);
  if (next->fd < 0) {
    set_test_err(test, MAJ_SYSTEM, errno);
    goto fail;
  }
  /* Connect socket, if it connects skip a step. Else change event state to next section */
  if (connect(next->fd, config.ai->ai_addr, config.ai->ai_addrlen) < 0) {
    if (errno == EINPROGRESS) {
      ssl_instance_set_callback(next, EV_WRITE, ssl_instance_check_connect);
    }
    else {
      set_test_err(test, MAJ_SYSTEM, errno);
       goto fail;
    }
  }
  else {
    ssl_instance_prepare_ssl(next);
    ssl_instance_set_callback(next, EV_WRITE, ssl_instance_ssl_connect);
  }

  g->tests.testoff++;
  return next;
 
fail:
  if (next) {
    close(next->fd);
    next->fd = -1;
    next->test = NULL;
  }
  return NULL;
}

/* This is the idle handler. The idle handler is activated by instances */
/* resetting into the INITIALIZED state. Such that there should always be 1 */
/* instance to take more work when the handler is activated. */
static void add_more_tests(
    struct ev_loop *loop,
    ev_idle *idle,
    int events)
{
  struct ssl_instance *i;
  ssl_test *next = NULL;

  /* All tests are done. Stop handler. */
  if (g->tests.testoff >= g->tests.testno) {
    ev_idle_stop(loop, idle);
    return;
  }

  /* Keep assigning tests until the pool has no more space */
  do {
    /* Note, the test offset is incremented in ssl_instance_pool_initialize_test */
    next = &g->tests.tests[g->tests.testoff];
    i = ssl_instance_pool_initialize_test(g->tls_instance_pool, config.concurrency, next);
  } while (i != NULL && g->tests.testoff < g->tests.testno);

  ev_idle_stop(loop, idle);
}

/* Checks the ssl_instance pool for those that have timed out,
 * this is a repeating timer. Not the most efficient way
 * to do it but its simple and effective */
static void check_timeouts(
    struct ev_loop *loop,
    ev_timer *timer,
    int events)
{
  ssl_instance *instance;
  int i;
  int sz = config.concurrency;
  ev_tstamp now = ev_now(loop);

  /* All tests are done and all instances are finished */
  if (g->tests.testoff >= g->tests.testno && g->concurrency_level == 0) {
    ev_timer_stop(loop, timer);
    return;
  }

  for (i=0; i < sz; i++) {
    instance = &g->tls_instance_pool[i];
    /* The connection has timed out */
    if (instance->state == STATE_STARTED && 
       (now - (instance->timeout + config.timeout)) >= 0) {
      ssl_instance_abort(instance, MAJ_SYSTEM, ETIMEDOUT);
    }
  }
}

/* Parse user inputted configuration */
static void parse_config(
    int argc,
    char **argv)
{
  int c;
  int rc;
  int optidx;

  int protocols = 0;
  int settls = 0;
  int settls1 = 0;
  int settls2 = 0;

  static struct option long_options[] = {
    { "help",        no_argument,       NULL, 'h' },
    { "ssl3",        no_argument,       NULL, '3' },
    { "no-tls1",     no_argument,       NULL, '0' },
    { "tls1",        no_argument,       NULL,  0  },
    { "no-tls1_1",   no_argument,       NULL, '1' },
    { "tls1_1",      no_argument,       NULL,  0  },
    { "no-tls1_2",   no_argument,       NULL, '2' },
    { "tls1_2",      no_argument,       NULL,  0  },
    { "verbose",     no_argument,       NULL, 'v' },
    { "concurrency", required_argument, NULL, 'n' },
    { "port",        required_argument, NULL, 'p' },
    { "host",        required_argument, NULL, 'H' },
    { "info",        no_argument,       NULL, 'i' },
    { "no-waf",      no_argument,       NULL, 'W' },
    { "timeout",     required_argument, NULL, 't' },
    { "pci",         required_argument, NULL, 'P' },
    { "no-cert-validation", no_argument, NULL, 'C'},
    {  0,            0,                 0,     0  },
  };

  memset(&config, 0, sizeof(config));

  config.certval = CERT_VAL;
  config.protocols = TLS1|TLS1_1|TLS1_2;

  while (1) {
    c = getopt_long(argc, argv, "ihCPSW012vn:p:H:t:", long_options, &optidx);
    if (c == -1)
      break;

    switch (c) {
      case 0:
        if (strcmp(long_options[optidx].name, "tls1") == 0) {
          protocols |= TLS1;
          if (settls) {
            fprintf(stderr, "The options '--tls1' and '--no-tls1' are mutually exclusive\n");
            exit(EXIT_FAILURE);
          }
          settls++;
        }
        if (strcmp(long_options[optidx].name, "tls1_1") == 0) {
          protocols |= TLS1_1;
          if (settls1) {
            fprintf(stderr, "The options '--tls1_1' and '--no-tls1_1' are mutually exclusive\n");
            exit(EXIT_FAILURE);
          }
          settls1++;
        }
        if (strcmp(long_options[optidx].name, "tls1_2") == 0) {
          protocols |= TLS1_2;
          if (settls2) {
            fprintf(stderr, "The options '--tls1_2' and '--no-tls1_2' are mutually exclusive\n");
            exit(EXIT_FAILURE);
          }
          settls2++;
        }
      break;

      case 'h':
        print_help();
        exit(1);
      break;

      case 'S':
        config.protocols |= SSL3;
      break;

      case 'C':
        config.certval = NO_CERT_VAL;
      break;

      case '0':
        config.protocols &= SSL3|TLS1_1|TLS1_2;
        if (settls) {
          fprintf(stderr, "The options '--tls1' and '--no-tls1' are mutually exclusive\n");
          exit(EXIT_FAILURE);
        }
        settls++;
      break;
      
      case '1':
        config.protocols &= SSL3|TLS1|TLS1_2;
        if (settls1) {
          fprintf(stderr, "The options '--tls1_1' and '--no-tls1_1' are mutually exclusive\n");
          exit(EXIT_FAILURE);
        }

        settls1++;
      break;

      case '2':
        config.protocols &= SSL3|TLS1|TLS1_1;
        if (settls2) {
          fprintf(stderr, "The options '--tls1_2' and '--no-tls1_2' are mutually exclusive\n");
          exit(EXIT_FAILURE);
        }
        settls2++;
      break;

      case 'v':
        config.verbose = VERBOSE;
      break;

      case 'W':
        config.nowaf = NO_WAF;
      break;

      case 'P':
        config.pci = PCI;
      break;

      case 'i':
        print_info();
        exit(0);
      break;

      case 't':
        config.timeout = atof(optarg);
        if (config.timeout <= 0 || config.timeout > MAX_TIMEOUT) {
          fprintf(stderr, "Error: The concurrency option set was invalid. Select a number between 1 and %.0f\n", MAX_TIMEOUT);
          exit(EXIT_FAILURE);
        }
      break;

      case 'n':
        config.concurrency = atoi(optarg);
        if (config.concurrency <= 0 || config.concurrency > MAX_CONCURRENCY) {
          fprintf(stderr, "Error: The concurrency option set was invalid. Select a number between 1 and %d\n", MAX_CONCURRENCY);
          exit(EXIT_FAILURE);
        }
      break;

      case 'H':
        config.host = strdup(optarg);
        if (!config.host)
          err(EXIT_FAILURE, "Cannot allocate config memory");
      break;

      case 'p':
        config.port = strdup(optarg);
        if (!config.port)
          err(EXIT_FAILURE, "Cannot allocate config memory");
      break;

      default:
        print_usage();
        print_help_bootstrap();
        exit(1);
      break;
    }
  }

  /* Check the options given. Set defaults for unset values */
  if (!config.concurrency)
    config.concurrency = DEFAULT_CONCURRENCY;

  if (!config.verbose)
    config.verbose = NO_VERBOSE;

  if (!config.port) {
    config.port = strdup(DEFAULT_PORT);
    if (!config.port)
      err(EXIT_FAILURE, "Cannot allocate config memory");
  }

  if (config.certval == NO_CERT_VAL)
    SSL_CTX_set_verify(g->tls, SSL_VERIFY_NONE, NULL);

  if (!config.timeout)
    config.timeout = DEFAULT_TIMEOUT;

  if (config.pci) {
    /* Always disable SSL3 and always disable WAF check */
    config.nowaf = NO_WAF;
    config.protocols &= TLS1|TLS1_1|TLS1_2;
  }

  /* Overrides protocol selection */
  config.protocols |= protocols;

  if (optind >= argc) {
    print_usage();
    print_help_bootstrap();
    exit(EXIT_FAILURE);
  }

  config.hostname = strdup(argv[optind]);
  /* Check hostname in DNS */
  rc = getaddrinfo(config.hostname, config.port, NULL, &config.ai);
  if (rc) {
    fprintf(stderr, "Cannot resolve domain name %s: %s\n", config.hostname, gai_strerror(rc));
    exit(EXIT_FAILURE);
  }

  if (!config.host) {
    config.host = strdup(config.hostname);
    if (!config.host)
      err(EXIT_FAILURE, "Cannot allocate config memory");
  }

  return;
}

/* Main */
int main(
    int argc,
    char **argv)
{
  init_global_state();
  init_openssl_library();

  parse_config(argc, argv);

  /* Create a list of tests which must be passed */
  create_waf_tests();

  /* Create some SSL3 and TLS instances */
  g->tls_instance_pool = ssl_instance_create(config.concurrency);

  /* Setup the idle watcher which will add tests to the queue */
  ev_idle_init(&g->idle, add_more_tests);
  ev_idle_start(EV_DEFAULT, &g->idle);

  /* Setup the timer watcher to timeout invalid connections */
  ev_timer_init(&g->timer, check_timeouts, .2, .2);
  ev_timer_start(EV_DEFAULT, &g->timer);

  /* Start event loop */
  ev_run(EV_DEFAULT, 0);

  printf("\nScan complete. Assessment: %s\n", g->success ? "\e[40m\e[32m\e[1mPASSED\e[0m" : "\e[40m\e[31m\e[1mFAILED\e[0m");

  exit(!g->success);
}
