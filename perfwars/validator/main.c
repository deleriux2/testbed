#include "database.h"
#include "common.h"
#include "manager.h"
/*
       #include "ippool.h"
       #include <netinet/in.h>
       #include <arpa/inet.h>
*/
#include <sys/resource.h>
#include <limits.h>
#include <getopt.h>

gnutls_certificate_credentials_t cred = NULL;

#define PROGNAME "pwvalidate"

struct config {
  char *canvas_path;
  char *checksum_path;
  char *hostname;
  char *port;
  int runtime;
  int timeout;
  int concurrency;
  float plot1x;
  float plot1y;
  float plot2x;
  float plot2y;
  char *random_seed_name;
  int workers;
  
} config = {
  "canvas.rng",
  NULL,
  NULL,
  "https",
  600,
  10000000,
  100,
  0.25,
  0.0,
  0.5,
  1.0,
  NULL,
  0,
};

static void print_usage(
    void)
{
  printf("Usage: "PROGNAME" [OPTION]... HOSTNAME [PORT] SEED\n");
}

static void print_help(
     void)
{
  printf("Usage: "PROGNAME" [OPTION]... HOSTNAME [PORT] SEED\n"
         "Test perfwars implementations against a service curve\n"
         "Example: "PROGNAME" -t 10 -r 100 -c 300 localhost:8443 \"my seed\"\n"
         "\n"
         "  -1 --bezier-path-1=X,Y   Sets the bezier curve of point 1 to X,Y\n"
         "                           where X and Y are between 0..1\n"
         "                           default: 0.00,0.25\n"
         "  -2 --bezier-path-2=X,Y   Sets the bezier curve of point 2 to X,Y\n"
         "                           where X and Y are between 0..1\n"
         "                           default: 0.00,0.50\n"
         "  -c --concurrency=NUM     Sets the maximum concurrency, which\n"
         "                           fixes the Y axis of the service curve\n"
         "                           default: 100\n"
         "  -C --canvas-path=PATH    Sets the path to the canvas file to PATH\n"
         "                           default: \"./canvas.rng\".\n"
         "  -h --help                Prints this help.\n"
         "  -k --checksum-path=PATH  Sets the path to a checksum file which\n"
         "                           contains the names and pre-computed\n"
         "                           checksums of the static entries in a \n"
         "                           file similar to the one produced by\n"
         "                           sha256sum, but including the key.\n"
         "                           default: none\n"
         "  -r --runtime=SECONDS     The maximum period of time the test\n"
         "                           should run for in SECONDS. This fixes\n" 
         "                           the X aces of the service curve\n"
         "                           default: 600\n"
         "  -t --timeout=SECONDS     The maximum period of time to SECONDS\n"
         "                           each round of the service curve to\n"
         "                           take. Fixes the number of rounds used\n"
         "                           against the curve.\n"
         "                           default: 10\n"
         "  -u --usage               Prints a brief usage message\n"
         "  -w --workers             The number of workers to process data.\n"
         "                           default: max number of cpus\n"
         "\n\n"
         "SERVICE CURVE\n"
         "The service curve is a bezier curve which the program will follow\n"
         "in order to test each program. Whilst the curve model remains constant\n"
         "the Y (concurrency) and the X (runtime) can be altered. This produces\n"
         "less or more aggressive forms of tests against the candidate system\n"
         "\nCANVAS FILE\n"
         "The canvas is a source of random data. It should be base64 encoded and\n"
         "can be any size, although 64 megabytes is sufficient. This is the random\n"
         "data source that the program uses to draw its random files from\n"
         "\nSEED\n"
         "The seed denotes the order by use of a weak RNG by which requests will be\n"
         "sent, the names of the requests, and their methods. It ensures all hosts\n"
         "tested receive the same request types in the (roughly) same order\n"
         "\n\n");

}


static void parse_config(
    int argc,
    char **argv)
{
  int c, rc;
  char *p;
  int option_index = 0;

  static struct option long_options[] = {
    { "help", no_argument, 0, 'h' },
    { "canvas-path", required_argument, 0, 'C' },
    { "checksum-path", required_argument, 0, 'k' },
    { "runtime", required_argument, 0, 'r' },
    { "timeout", required_argument, 0, 't' },
    { "concurrency", required_argument, 0, 'c' },
    { "bezier-path-1", required_argument, 0, '1' },
    { "bezier-path-2", required_argument, 0, '2' },
    { "usage", no_argument, 0, 'u' },
    { "workers", required_argument, 0, 'w' },
    { 0, 0, 0, 0 }
  }; 

  while (1) {
    c = getopt_long(argc, argv, "1:2:c:C:hk:r:t:uw:", long_options,
                    &option_index);
    if (c < 0)
      break;

    switch(c) {

      case '1':
        rc = sscanf(optarg, "%f,%f", &config.plot1x, &config.plot1y);
        if (rc != 2) {
          fprintf(stderr, "Invalid argument. The -1 option takes an argument of the form \"x,y\"\n");
          goto fail;
        }
        if (config.plot1x < 0 || config.plot1x > 1) {
          fprintf(stderr, "Invalid argument. The -1 option values must be between 0 ... 1\n");
          goto fail;
        }
        if (config.plot1y < 0 || config.plot1y > 1) {
          fprintf(stderr, "Invalid argument. The -1 option values must be between 0 ... 1\n");
          goto fail;
        }
      break;

      case '2':
        rc = sscanf(optarg, "%f,%f", &config.plot2x, &config.plot2y);
        if (rc != 2) {
          fprintf(stderr, "Invalid argument. The -2 option takes an argument of the form \"x,y\"\n");
          goto fail;
        }
        if (config.plot2x < 0 || config.plot2x > 1) {
          fprintf(stderr, "Invalid argument. The -2 option values must be between 0 ... 1\n");
          goto fail;
        }
        if (config.plot2y < 0 || config.plot2y > 1) {
          fprintf(stderr, "Invalid argument. The -2 option values must be between 0 ... 1\n");
          goto fail;
        }
      break;

      case 'c':
        config.concurrency = atoi(optarg);
        if (config.concurrency <= 0 || config.concurrency > MAX_CONCURRENCY) {
          fprintf(stderr, "Invalid argument. The -c option values must be between 1 ... %d\n", MAX_CONCURRENCY);
          goto fail;
        }
      break;

      case 'C':
        config.canvas_path = strdup(optarg);
      break;

      case 'h':
        print_help();
        exit(1);;
      break;

      case 'k':
        config.checksum_path = strdup(optarg);
      break;

      case 'r':
        config.runtime = atoi(optarg);
        if (config.runtime <= 0 || config.runtime > MAX_RUNTIME) {
          fprintf(stderr, "Invalid argument. The -r option values must be between 2 ... %d\n", MAX_RUNTIME);
          goto fail;
        }
      break;

      case 't':
        config.timeout = atoi(optarg);
        if (config.timeout <= 0 || config.timeout > 120) {
          fprintf(stderr, "Invalid argument. The -t option values must be between 2 .... 120\n");
          goto fail;
        }
        config.timeout *= 1000000;
      break;

      case 'w':
        config.workers = atoi(optarg);
        if (config.workers <= 0 || config.workers > NUM_WORKERS) {
          fprintf(stderr, "Invalid argument. The -w option values must be between 1 .... %d \n", NUM_WORKERS);
          goto fail;
        }
      break;


      case 'u':
        print_help();
        exit(1);;
      break;

      default:
        print_usage();
        exit(1);
      break;
    }
  }

  if (argc-optind < 2) {
    fprintf(stderr, "Must provide a hostname and random seed value\n");
    print_usage();
    goto fail;
  }

  /* If runtime is less than timeout */
  if ((config.runtime*1000000) < config.timeout) {
    fprintf(stderr, "Invalid argument.  The runtime parameter must be at least equal to the timeout parameter\n");
    goto fail;
  }

  if (argc-optind == 2) {
    config.hostname = strdup(argv[optind]);
    optind++;
  }
  else if (argc-optind == 3) {
    config.hostname = strdup(argv[optind]);
    config.port = strdup(argv[optind+1]);
    optind+=2;
  }

  /* Process random seed */
  rc = strlen(argv[optind]);
  if (rc <= 0) {
    fprintf(stderr, "Cannot process seed given\n");
    goto fail;
  }
  config.random_seed_name = strdup(argv[optind]);
  optind++;

  return;

fail:
  exit(1);
  
}

static void init_libs(
    void)
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
}

int main(
    int argc,
    char **argv)
{
  init_libs();
  parse_config(argc, argv);
  struct rlimit lim;
  struct sigaction act;

/*
  struct sockaddr_in *in;
  ippool_t *ip;

  char name[16];
  ip = ippool_init_src(config.hostname, config.port);
  if (ip == NULL)
    exit(1);
  for (int i=0; i < 10; i++) {
    in = ippool_next(ip);
    printf("%s:%d\n", inet_ntoa(in->sin_addr), ntohs(in->sin_port));
  }
  ippool_destroy(ip);
  printf("\n");
  ip = ippool_init_dst(config.hostname, config.port);
  if (ip == NULL)
    exit(1);
  for (int i=0; i < 10; i++) {
    in = ippool_next(ip);
    printf("%s:%d\n", inet_ntoa(in->sin_addr), ntohs(in->sin_port));
  }
  exit(1);
/*/


  /* Configure the concurrency setting */
  memset(&lim, 0, sizeof(lim));
  if (getrlimit(RLIMIT_NOFILE, &lim) < 0)
    err(EXIT_FAILURE, "Unable to acquire limits");

  if (lim.rlim_max < config.concurrency + 100)
    errx(EXIT_FAILURE, "Unable to support concurrency as max open file limit" \
                       " is %d. Need %d", 
                       lim.rlim_max, config.concurrency + 100);

  if (lim.rlim_cur < config.concurrency + 100) {
    lim.rlim_cur = config.concurrency + 100;
    if (setrlimit(RLIMIT_NOFILE, &lim) < 0)
      err(EXIT_FAILURE, "Cannot set max file limit");
  }
 
  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;
  if (sigaction(SIGPIPE, &act, NULL) < 0)
    err(EXIT_FAILURE, "Cannot set action on signal");
  

  manager_t *manager = manager_init(
    config.canvas_path, config.checksum_path, config.hostname,
    config.port, config.runtime, config.timeout, config.concurrency,
    config.plot1x, config.plot1y, config.plot2x, config.plot2y,
    config.random_seed_name, config.workers);
  if (!manager)
    exit(1);
  while (manager_run_round(manager));

  printf("%s\n", manager_statistics(manager));

  exit(0);
}
