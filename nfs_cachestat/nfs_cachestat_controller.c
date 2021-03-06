#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/uio.h>
#include <time.h>

#define PROGNAME "nfs_statcache_controller"
#define SOCKPATH "/var/tmp/nfs_cachestat.sock"

#define MIN_ROUNDS 1
#define MAX_ROUNDS 65535

#define UNIX_PATH_MAX 108

/* Commands they accept */
#define CTRL_CONFIG       0x000LU
#define CTRL_READ         0x001LU
#define CTRL_WRITE        0x002LU
#define CTRL_TRUNCATE     0x003LU
#define CTRL_STAT         0x004LU
#define CTRL_MAP          0x005LU
#define CTRL_SEEK         0x006LU

/* Results we get back */
#define CTRL_CONFIG_DONE  0X100LU
#define CTRL_DONE         0x101LU
#define CTRL_ERROR        0x102LU
#define CTRL_READY        0x103LU

#define RPCFILE           "/proc/net/rpc/nfs"

int clientfd;

struct nfsstat {
  uint64_t calls;
  uint64_t null;
  uint64_t getattr;
  uint64_t setattr;
  uint64_t lookup;
  uint64_t access;
  uint64_t readlink;
  uint64_t read;
  uint64_t write;
  uint64_t create;
  uint64_t mkdir;
  uint64_t symlink;
  uint64_t mknod;
  uint64_t remove;
  uint64_t rmdir;
  uint64_t rename;
  uint64_t link;
  uint64_t readdir;
  uint64_t readdirplus;
  uint64_t fsstat;
  uint64_t fsinfo;
  uint64_t pathconf;
  uint64_t commit;
};

static struct {
  int rounds;
  int rounds_per_iteration;
  char path[PATH_MAX];
  char sockpath[UNIX_PATH_MAX];
  char *instruction;
  int in_sz;
  ssize_t filesize;
} config;


static void print_help(
    void)
{
  fprintf(stderr, "The NFS stat cache worker.\n"
                  "%s [options] <path_to_file>\n"
                  "    --size     -s        The size of the file to do work on\n"
                  , PROGNAME);
}

void handle_signals(
    int sig)
{
  exit(0);
}

static void parse_config(
    int argc,
    char **argv)
{
  int tmp, i;
  char c;
  int error = 0;
  char pathcomp[2][PATH_MAX];

  /* Configure config defaults */
  strncpy(config.sockpath, SOCKPATH, UNIX_PATH_MAX);

  struct option opts[] = {
    { "help", no_argument, 0, 'h' },
    { "rpi", required_argument, 0, 'r' },
    { "socket", required_argument, 0, 'S' },
    { "size", required_argument, 0, 's' },
    { 0, 0, 0 }
  };

  while ((c = getopt_long(argc, argv, "hS:", opts, &optind)) != -1) {
    switch(c) {
       case 'S':
         strncpy(config.sockpath, optarg, UNIX_PATH_MAX);
       break;

       case 'h':
       case '?':
         print_help();
         exit(EX_SOFTWARE);
       break;

       default:
         abort();
    }
  }

  if (optind >= argc) {
    errx(EX_SOFTWARE, "Must supply number of rounds and descriptor string");
  }
  else {
    config.rounds = atoi(argv[optind++]);
    if (config.rounds < MIN_ROUNDS || config.rounds >= MAX_ROUNDS)
      errx(EX_SOFTWARE, "Rounds must be between %d and %d", MIN_ROUNDS, MAX_ROUNDS);
  }

  if (optind >= argc)
    errx(EX_SOFTWARE, "Must supply a instruction string");
  tmp = strlen(argv[optind]);
  for (i=0; i < tmp; i++) {
    if (argv[optind][i] == 'k')
      continue;
    else if (argv[optind][i] == 'm')
      continue;
    else if (argv[optind][i] == 'r')
      continue;
    else if (argv[optind][i] == 's')
      continue;
    else if (argv[optind][i] == 'S')
      continue;
    else if (argv[optind][i] == 'w')
      continue;
    else if (argv[optind][i] == 't')
      continue;
    else
      errx(EX_SOFTWARE, "Instruction string must be one of \"see(k),(m)ap,(r)ead,(s)tat on controller,(S)tat on worker,(t)runcate,(w)rite");
  }
  config.in_sz = tmp;
  config.instruction = argv[optind++];

  return;
}

int get_nfs_statistics(
    struct nfsstat *stat)
{
  FILE *sfile = fopen(RPCFILE, "r");
  char buf[4096];
  uint64_t nil;

  memset(stat, 0, sizeof(struct nfsstat));
  if (sfile == NULL) {
    warn("Cannot get stats, returning zeroes");
    return -1;
  }

  while (!feof(sfile)) {
    if (fgets(buf, 4096, sfile) == NULL)
      break;

    if (sscanf(buf, "rpc %llu", &stat->calls) == 1)
      continue;
    if (sscanf(buf, "proc3 %llu %llu %llu %llu %llu %llu %llu %llu "
                      "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu "
                      "%llu %llu %llu %llu %llu",
              &nil, &stat->null, &stat->getattr, &stat->setattr, &stat->lookup, 
              &stat->access, &stat->readlink, &stat->read, &stat->write, 
              &stat->create, &stat->mkdir, &stat->symlink, &stat->mknod, 
              &stat->remove, &stat->rmdir, &stat->rename, &stat->link, 
              &stat->readdir, &stat->readdirplus, &stat->fsstat, &stat->fsinfo, 
              &stat->pathconf, &stat->commit) == 23)
      return 0;
  }
  return -1;
}

inline struct nfsstat nfs_diff_stats(
    struct nfsstat n,
    struct nfsstat t)
{
  struct nfsstat d;
  d.calls = t.calls - n.calls;
  d.null = t.null - n.null;
  d.getattr = t.getattr - n.getattr;
  d.setattr = t.setattr - n.setattr;
  d.lookup = t.lookup - n.lookup;
  d.access = t.access - n.access;
  d.readlink = t.readlink - n.readlink;
  d.read = t.read - n.read;
  d.write = t.write - n.write;
  d.create = t.create - n.create;
  d.mkdir = t.mkdir - n.mkdir;
  d.symlink = t.symlink - n.symlink;
  d.mknod = t.mknod - n.mknod;
  d.remove = t.remove - n.remove;
  d.rmdir = t.rmdir - n.rmdir;
  d.rename = t.rename - n.rename;
  d.link = t.link - n.link;
  d.readdir = t.readdir - n.readdir;
  d.readdirplus = t.readdirplus - n.readdirplus;
  d.fsstat = t.fsstat - n.fsstat;
  d.fsinfo = t.fsinfo - n.fsinfo;
  d.pathconf = t.pathconf - n.pathconf;
  d.commit = t.commit - n.commit;
  return d;
}

int timediff(
    struct timespec *diff,
    int (*func)(int fd),
    int fd)
{
  unsigned long long valdiff = 0, val = 0, val2 = 0;
  struct timespec then, now;
  int sz;
  int rc;

  if (clock_gettime(CLOCK_REALTIME, &then) < 0)
    err(EX_OSERR, "Cannot get then time");

  rc = func(fd);

  if (clock_gettime(CLOCK_REALTIME, &now) < 0)
    err(EX_OSERR, "Can not get now time");

  val = (now.tv_sec * 1000000000LLU) + now.tv_nsec;
  val2 = (then.tv_sec * 1000000000LLU) + then.tv_nsec;
  valdiff = val - val2;

  diff->tv_sec = (valdiff / 1000000000LLU);
  diff->tv_nsec = (valdiff % 1000000000LLU);

  return rc;
}

void check_readiness(
    int clientfd)
{
  uint32_t cmdtype;
  if (recv(clientfd, &cmdtype, sizeof(cmdtype), 0) < 0)
    err(EX_OSERR, "Unable to recieve data from socket");
  if (cmdtype != CTRL_READY)
    err(EX_PROTOCOL, "Server sent a response we did not expect");
  return;
}

int send_cmd_request(
    int clientfd,
    struct timespec *time,
    int protocol,
    struct nfsstat *diff)
{
  int error;
  struct iovec vec[26];
  uint32_t cmdtype = protocol;

  if (send(clientfd, &cmdtype, sizeof(cmdtype), 0) <= 0)
    err(EX_OSERR, "Unable to send data to socket");

  if (recv(clientfd, &cmdtype, sizeof(cmdtype), 0) <= 0)
    err(EX_OSERR, "Unable to receve data from socket");

  if (cmdtype == CTRL_ERROR) {
    vec[0].iov_base = &error;
    vec[0].iov_len = sizeof(error);
    if (readv(clientfd, vec, 1) <= 0)
      err(EX_OSERR, "Cannot retrieve error");
    return -error;
  }

  else if (cmdtype == CTRL_DONE) {
    vec[0].iov_base = &error;             vec[0].iov_len = sizeof(error);
    vec[1].iov_base = &time->tv_sec;      vec[1].iov_len = sizeof(time->tv_sec);
    vec[2].iov_base = &time->tv_nsec;     vec[2].iov_len = sizeof(time->tv_nsec);

    vec[3].iov_base = &diff->calls;        vec[3].iov_len = sizeof(uint64_t);
    vec[4].iov_base = &diff->null;         vec[4].iov_len = sizeof(uint64_t);
    vec[5].iov_base = &diff->getattr;      vec[5].iov_len = sizeof(uint64_t);
    vec[6].iov_base = &diff->setattr;      vec[6].iov_len = sizeof(uint64_t);
    vec[7].iov_base = &diff->lookup;       vec[7].iov_len = sizeof(uint64_t);
    vec[8].iov_base = &diff->access;       vec[8].iov_len = sizeof(uint64_t);
    vec[9].iov_base = &diff->readlink;     vec[9].iov_len = sizeof(uint64_t);
    vec[10].iov_base = &diff->read;        vec[10].iov_len = sizeof(uint64_t);
    vec[11].iov_base = &diff->write;       vec[11].iov_len = sizeof(uint64_t);
    vec[12].iov_base = &diff->create;      vec[12].iov_len = sizeof(uint64_t);
    vec[13].iov_base = &diff->mkdir;       vec[13].iov_len = sizeof(uint64_t);
    vec[14].iov_base = &diff->symlink;     vec[14].iov_len = sizeof(uint64_t);
    vec[15].iov_base = &diff->mknod;       vec[15].iov_len = sizeof(uint64_t);
    vec[16].iov_base = &diff->remove;      vec[16].iov_len = sizeof(uint64_t);
    vec[17].iov_base = &diff->rmdir;       vec[17].iov_len = sizeof(uint64_t);
    vec[18].iov_base = &diff->rename;      vec[18].iov_len = sizeof(uint64_t);
    vec[19].iov_base = &diff->link;        vec[19].iov_len = sizeof(uint64_t);
    vec[20].iov_base = &diff->readdir;     vec[20].iov_len = sizeof(uint64_t);
    vec[21].iov_base = &diff->readdirplus; vec[21].iov_len = sizeof(uint64_t);
    vec[22].iov_base = &diff->fsstat;      vec[22].iov_len = sizeof(uint64_t);
    vec[23].iov_base = &diff->fsinfo;      vec[23].iov_len = sizeof(uint64_t);
    vec[24].iov_base = &diff->pathconf;    vec[24].iov_len = sizeof(uint64_t);
    vec[25].iov_base = &diff->commit;      vec[25].iov_len = sizeof(uint64_t);

    if (readv(clientfd, vec, 26) <= 0)
      err(EX_OSERR, "Cannot receive data from socket");
    return error;
  }

  else {
    err(EX_PROTOCOL, "Server sent a response we did not expect");
  }
}


void get_server_config(
    int clientfd)
{
  uint32_t cmdtype;
  uint32_t error;
  struct iovec vec[4];

  cmdtype = CTRL_CONFIG;

  if (send(clientfd, &cmdtype, sizeof(cmdtype), 0) < 0)
    err(EX_OSERR, "Lost connection to server");

  if (recv(clientfd, &cmdtype, sizeof(cmdtype), 0) < 0)
    err(EX_OSERR, "Lost connection to server");

  if (cmdtype == CTRL_ERROR) {
    vec[0].iov_base = &error;
    vec[0].iov_len = sizeof(error);
    if (readv(clientfd, vec, 1) < 0)
      err(EX_OSERR, "Cannot retrieve error");
    errno = error;
    err(EX_OSERR, "Error returned from server");
  }
    

  vec[0].iov_base = &config.rounds_per_iteration;
  vec[0].iov_len = sizeof(config.rounds_per_iteration);
  vec[1].iov_base = config.path;
  vec[1].iov_len = sizeof(config.path);
  vec[2].iov_base = config.sockpath;
  vec[2].iov_len = sizeof(config.sockpath);
  vec[3].iov_base = &config.filesize;
  vec[3].iov_len = sizeof(config.filesize);
  if (readv(clientfd, vec, 4) < 0)
    err(EX_OSERR, "Cannot retrieve config");

}

int perform_stat_request(
    int fd)
{
  struct stat st;
  int rc;
  rc = stat(config.path, &st);
  return rc;
}


int main(
    int argc,
    char **argv)
{
  int rc, h, i;
  struct timespec timer = {0,0};
  struct sockaddr_un un = { AF_UNIX, 0 };
  struct nfsstat stats, then, now;
  parse_config(argc, argv);

  /* Setup signal handlers */
  struct sigaction act;
  memset(&act, 0 , sizeof(act));
  act.sa_handler = handle_signals;;
  if (sigaction(SIGINT, &act, NULL) < 0)
    err(EX_OSERR, "Cannot setup signal handlers");
  if (sigaction(SIGPIPE, &act, NULL) < 0)
    err(EX_OSERR, "Cannot setup signal handlers");

  /* Setup socket connection */
  strncpy(un.sun_path, config.sockpath, UNIX_PATH_MAX);
  clientfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (clientfd < 0)
    err(EX_OSERR, "Cannot connect to socket");
  if (connect(clientfd, (struct sockaddr *)&un, sizeof(un)) < 0)
    err(EX_OSERR, "Cannot connect to socket");

  /* Preliminary check */
  check_readiness(clientfd);
  printf("Server is ready for us..\n");
  /* Get the configuration of this server */
  get_server_config(clientfd);
  printf("Server file: %s\nFile Size: %d\n", config.path, config.filesize);

  for (h=0; h < config.rounds; h++) {
    memset(&stats, 0, sizeof(stats));
    for (i=0; i < config.in_sz; i++) {
      switch(config.instruction[i]) {
        case 'k':
          rc = send_cmd_request(clientfd, &timer, CTRL_SEEK, &stats);
        break;
        case 'm':
          rc = send_cmd_request(clientfd, &timer, CTRL_MAP, &stats);
        break;
        case 'r':
          rc = send_cmd_request(clientfd, &timer, CTRL_READ, &stats);
        break;
        case 's':
          get_nfs_statistics(&then);
          rc = timediff(&timer, perform_stat_request, clientfd);
          get_nfs_statistics(&now);
          stats = nfs_diff_stats(then, now);
        break;
        case 'S':
          rc = send_cmd_request(clientfd, &timer, CTRL_STAT, &stats);
        break;
        case 't':
          rc = send_cmd_request(clientfd, &timer, CTRL_TRUNCATE, &stats);
        break;
        case 'w':
          rc = send_cmd_request(clientfd, &timer, CTRL_WRITE, &stats);
        break;
        default:
          abort();
        break;
      }
      printf("%c rc: %d, %d.%09d, Calls: %llu, Gettr: %llu, Reads: %llu, Writes: %llu\n", 
                config.instruction[i], rc, timer.tv_sec, timer.tv_nsec,
                stats.calls, stats.getattr, stats.read, stats.write);
    }
  }
  /* Trialling out a read request */
  //rc = send_cmd_request(clientfd, &timer, CTRL_READ);
  //printf("read  rc: %d, %d.%09d\n", rc, timer.tv_sec, timer.tv_nsec);
  /* Trialling out a write request */
  //rc = send_cmd_request(clientfd, &timer, CTRL_WRITE);
  //printf("write rc: %d, %d.%09d\n", rc, timer.tv_sec, timer.tv_nsec);
  /* Trialling out a truncate request */
  //rc = send_cmd_request(clientfd, &timer, CTRL_TRUNCATE);
  //printf("trunc rc: %d, %d.%09d\n", rc, timer.tv_sec, timer.tv_nsec);
  /* Trialling out a stat request */
  //rc = perform_stat_request(config.path);

  exit(0);
}
