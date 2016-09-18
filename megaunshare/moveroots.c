#include "common.h"

#define PROGNAME "megaunshare"

struct config config;

static void usage() {
  printf("Usage: %s [options] BASEDIR -- COMMAND ARGS \n", PROGNAME);
  printf("Attempt to create a new container\n");
  printf("\n");
  printf("  --verbose   -v    Be verbose with setup output.\n");
  printf("  --uid       -u    The UID to switch to.\n");
  printf("  --gid       -g    The GID to switch to.\n");
  printf("  --range     -r    The number of ID's to create\n");
  printf("\n");
  exit(2);
}

static void parse_config(
    const int argc,
    char **argv)
{
  static struct option long_options[] = {
    { "verbose", no_argument,  0, 'v' },
    { "uid", required_argument, 0, 'u' },
    { "gid", required_argument, 0, 'g' },
    { "range", required_argument, 0, 'r'},
    { 0, 0, 0, 0 }
  };
  char c, *e;
  int opt_idx = 0;
  struct stat st;

  config.uid = -1;
  config.gid = -1;

  if (argc == 1)
    usage();

  while (1) {
 
    c = getopt_long(argc, argv, "vu:g:r:", long_options,
                     &opt_idx);

    if (c == -1)
      break;

    switch(c) {

      case 'g':
        config.uid = strtoul(optarg, &e, 10);
        if (*optarg == 0 || *e != 0)
          usage();
      break;

      case 'r':
        config.range = strtoul(optarg, &e, 10);
        if (*optarg == 0 || *e != 0)
          usage();
      break;

      case 'u':
        config.gid = strtoul(optarg, &e, 10);
        if (*optarg == 0 || *e != 0)
          usage();
      break;

      case 'v':
        config.verbose = 1;
      break;

      default:
        usage();
      break;
    }
  }

  if (optind < argc) {
    /* Make sure basedir is sane */
    strncpy(config.basedir, argv[optind], PATH_MAX);
    if (access(config.basedir, F_OK) < 0) {
      warn("Could not use selected basedir");
      usage();
    }
    if (stat(config.basedir, &st) < 0) {
      warn("Could not stat basedir");
      usage();
    }
    if (!S_ISDIR(st.st_mode)) {
      warnx("Basedir must be a directory");
      usage();
    }

    optind++;
    if (optind == argc) {
      warnx("You must supply a command to run");
      usage();
    }

    strncpy(config.command, argv[optind], PATH_MAX);
    config.cmdargs = argc - optind;
  }
  else {
    usage();
  }

  return;
}

int main(
    const int argc,
    char **argv)
{
  memset(&config, 0, sizeof(config));

  parse_config(argc, argv);

  create_container();
  exit(0);
}
