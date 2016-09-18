#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include <signal.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <GeoIP.h>

#include "nfc_stats.h"

#define MAX_COUNTRIES   256
#define MAX_QUEUE_RANGE 128
#define MAX_FILTERS     4096
#define QUEUE_SIZE      32000
#define MAX_PACKETS     1048576
#define BUFSZ           32768
#define DIR_SRC         0
#define DIR_DST         1

#define DEFAULT_COUNTRY "DEFAULT"

struct qdata;

/* Models the filter config file */
typedef struct filter {
  unsigned short group_s;
  unsigned short group_e;
  unsigned int direction;
  unsigned int verdict;
  int country_num;
  char countries[MAX_COUNTRIES][8];
} filter_t;

/* Models the thread instance */
typedef struct nfcountry {
  /* The thread identifier */
  int id;
  pthread_t thread;
  int netlinkfd;
  struct nfq_handle *qh;
  struct {
    struct nfq_q_handle *q;
    unsigned short gr;
    struct qdata *qd;
  } handles[MAX_FILTERS];
  int nhandles;
  filter_t *filters;
  GeoIP *ipdb;
  int nfilters;
  char errbuf[256];
} nfcountry_t;

/* Global data structure */
struct {
  char *filter_file;
  char *geoip_file;
  char *stats_file;
  nfcountry_t *threads;
  filter_t *filters;
  int nfilters;
  int ncpus;
  sigset_t sigs;
  nfc_stats_t *stats;
} globals;

struct qdata {
  nfcountry_t *nfc;
  unsigned int gr;
};


static int parse_filter_file(const char *filterfile, struct filter **filter_result);
static int nfq_load_queues(nfcountry_t *nfc);
static int nfq_handle_recv(struct nfq_q_handle *group, struct nfgenmsg *nfmsg, struct nfq_data *nfdata, void *data);
static void init_globals(void);
static void initialize_threads(void);
static void reload_config(void);
static int netlink_recv(nfcountry_t *nfc);
static void * worker_thread(void *);
static struct nfq_q_handle * nfq_handle_setup(nfcountry_t *nfc, unsigned short groupnum, struct qdata **qd);

inline static void set_sig(int how);

inline static void set_sig(
    int how)
{
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGRTMIN+1);
  pthread_sigmask(how, &set, NULL);
}

static void init_globals(
    void)
{
  memset(&globals, 0, sizeof(globals));
  globals.ncpus = sysconf(_SC_NPROCESSORS_ONLN);
}

/* Retrieves layer 3 IP from packet */
static int packet_get_s_addr(
    char *buf,
    char addr[INET_ADDRSTRLEN])
{
  if (inet_ntop(AF_INET, &buf[12], addr, INET_ADDRSTRLEN) == NULL)
    return -1;

  return 0;
}

/* Retrieves layer 3 IP from packet */
static int packet_get_d_addr(
    char *buf,
    char addr[INET_ADDRSTRLEN])
{
  if (inet_ntop(AF_INET, &buf[16], addr, INET_ADDRSTRLEN) == NULL)
    return -1;

  return 0;
}

/* Read the filter file and parse */
static int parse_filter_file(
    const char *filterfile,
    filter_t **filter_result)
{
  FILE *filters = NULL;
  struct filter *filt = NULL;
  int i,j;
  int filtnum=0;
  int lineno = 0;
  char line[2048];
  unsigned short group_s;
  unsigned short group_e;
  char direction[5];
  char country[512];
  char verdict[32];
  char *l, *p;

  filt = calloc(MAX_FILTERS, sizeof(filter_t));
  if (!filt) {
    warn("Cannot find memory for filters");
    goto fail;
  }

  filters = fopen(filterfile, "r");
  if (!filters) {
    warn("Cannot open filter file");
    goto fail;
  }

  while (!feof(filters)) {
    lineno++;
    memset(line, 0, sizeof(line));
    memset(direction, 0, sizeof(direction));
    memset(country, 0, sizeof(country));
    memset(verdict, 0, sizeof(verdict));

    if (fgets(line, 2047, filters) == NULL) {
      if (ferror(filters)) {
        warn("Cannot read filter file");
        break;
      }
    }
    /* Skip empty lines */
    if (line[0] == '\n')
      continue;
    if (strlen(line) == 0)
      break;

    /* Skip comments */
    if (line[0] == '#')
      continue;
    if (sscanf(line, "%hu:%hu %s %s %s\n", &group_s, &group_e, direction, country, verdict) != 5) {
      warnx("Cannot parse line %d in filter file %s", lineno, filterfile);
      goto fail;
    }

    /* Group parse */
    if (group_s < 0 || group_e < 0) {
      warnx("Cannot parse line %d in filter file %s: group must be between 0 and 65535", lineno, filterfile);
      goto fail;
    }

    if ((group_e - group_s) > MAX_QUEUE_RANGE) {
      warnx("Cannot parse line %d in filter file %s: group range is too large. Max %d.", lineno, filterfile, MAX_QUEUE_RANGE);
      goto fail;
    }

    if (group_s > group_e) {
      warnx("Cannot parse line %d in filter file %s: start group must be smaller than end group", lineno, filterfile);
      goto fail;
    }

    /* Warn if group is bigger than thread count */
    if ((group_e - group_s) > globals.ncpus) {
      fprintf(stderr, "WARNING: on line %d in filter file %s the group range "
            "is larger than the total CPUs active on the system!\nThis configuration is not recommended.\n",
            lineno, filterfile);
    }

    /* Check that the group is not already in the list and that it does not overlap with another entry */
    for (i=0; i < filtnum; i++) {
      if ((group_s >= filt[i].group_s && group_s <= filt[i].group_e) ||
          (group_e >= filt[i].group_s && group_e <= filt[i].group_e)) {
        warnx("Cannot parse line %d in filter file %s: group must be unique in the file and "
              "not overlap with other groups.", lineno, filterfile);
        goto fail;
      }
    }
    filt[filtnum].group_s = group_s;
    filt[filtnum].group_e = group_e;
   
    /* Direction parse */
    if (strcmp(direction, "DST") == 0) {
      filt[filtnum].direction = DIR_DST;
    }
    else if (strcmp(direction, "SRC") == 0) {
      filt[filtnum].direction = DIR_SRC;
    }
    else {
      warnx("Cannot parse line %d in filter file %s: direction must be 'SRC' or 'DST'", lineno, filterfile);
      filtnum++;
      goto fail;
    }

    /* Country parse */
    l = country;
    p = country;
    while ((l = strsep(&p, ",")) != NULL) {
      if (strlen(l) != 7 && strlen(l) != 2) {
        warnx("Cannot parse line %d in filter file %s: countries codes must be 2 or 7 characters but '%s' is not", lineno, filterfile, l);
        filtnum++;
        goto fail;
      }
      strncpy(filt[filtnum].countries[filt[filtnum].country_num++], l, 7);
    }

    /* Verdict parse */
    if (strcmp(verdict, "ACCEPT") == 0) {
      filt[filtnum].verdict = NF_STOP;
    }
    else if (strcmp(verdict, "DROP") == 0) {
      filt[filtnum].verdict = NF_DROP;
    }
    else {
      filtnum++;
      warnx("Cannot parse line %d in filter file %s: verdict must be 'ACCEPT' or 'DROP'", lineno, filterfile);
      goto fail;
    }
    filtnum++;
  }

  /* Reallocate the filter list */
  filt = realloc(filt, filtnum * sizeof(struct filter));

  *filter_result = filt;
  fclose(filters);
  return filtnum;

fail:
  fclose(filters);
  if (filt) {
    free(filt);
  }
  return -1;
}


/* Retrieves data from netlink and passes for queue processing */
static int netlink_recv(
    nfcountry_t *nfc)
{
  int sz;
  char buf[BUFSZ] __attribute__ ((aligned));

  set_sig(SIG_UNBLOCK);
  sz = recv(nfc->netlinkfd, buf, BUFSZ, 0);
  set_sig(SIG_BLOCK);
  if (sz < 0 && errno == EINTR)
    return 0;
  else if (sz < 0)
    return -1;

  nfq_handle_packet(nfc->qh, buf, sz);

  return sz;
}

/* Set up a group if one is required */
static struct nfq_q_handle * nfq_handle_setup(
    nfcountry_t *nfc,
    unsigned short groupnum,
    struct qdata **their_qd)
{
  struct nfq_q_handle *qh = NULL;
  struct qdata *qd = malloc(sizeof(struct qdata));

  if (!qd) {
    fprintf(stderr, "Thread %d cannot allocate qdata: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    goto fail;
  }
  qd->nfc = nfc;
  qd->gr = groupnum;

  if ((qh = nfq_create_queue(nfc->qh, groupnum, &nfq_handle_recv, qd)) == NULL) {
    fprintf(stderr, "Thread %d could not bind to group: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    goto fail;
  }

  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0x0080) < 0) {
    fprintf(stderr, "Thread %d could not set group mode: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    goto fail;
  }
  if (nfq_set_queue_maxlen(qh, MAX_PACKETS) < 0) {
    fprintf(stderr, "Thread %d could not set group buffer size: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    goto fail;
  }

  *their_qd = qd;
  return qh;

fail:
  if (qh)
    nfq_destroy_queue(qh);
  return NULL;
}


/* This callback handles the actual decision making */
static int nfq_handle_recv(
    struct nfq_q_handle *group,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfdata,
    void *data)
{
  struct qdata *qd = (struct qdata *)data;
  struct nfqnl_msg_packet_hdr *ph = NULL;
  struct nfq_q_handle *q = NULL;
  nfcountry_t *nfc = qd->nfc;
  filter_t *filter;
  int i,j;
  int found=0;
  int id;
  char addr[INET_ADDRSTRLEN];
  unsigned char *payload = alloca(192);
  const char *country = NULL;
  memset(payload, 0, sizeof(payload));

  ph = nfq_get_msg_packet_hdr(nfdata);
  id = ntohl(ph->packet_id);
  /* Match the packet to its group */
  for (i=0; i < nfc->nhandles; i++) {
    if (qd->gr == nfc->handles[i].gr) {
      q = nfc->handles[i].q;
      found = 1;
      break;
    }
  }
  /* Should not occur, maybe happens if a stray packet arrives from an old queue */
  if (!found) {
    fprintf(stderr, "Thread %d received stray packet id %d from group %d\n", nfc->id, id, qd->gr);
    return 0;
  }

  /* Get packet payload, expected to always succeed */
  assert(nfq_get_payload(nfdata, &payload));

  /* Find matching filter */
  found = 0;
  for (i=0; i < nfc->nfilters; i++) {
    filter = &nfc->filters[i];
    for (j=filter->group_s; j <= filter->group_e; j++) {
      if (qd->gr == j) {
        found = 1;
        break;
      }
    }
  }
  /* Should not occur. This is a bug if it does */
  if (!found) {
    fprintf(stderr, "Thread %d received stray packet id %d from group %d\n", nfc->id, id, qd->gr);
    return 0;
  }


  /* Fetch direction we are inspecting and get country */
  if (filter->direction == DIR_SRC) {
    packet_get_s_addr(payload, addr);
    country = GeoIP_country_code_by_addr(nfc->ipdb, addr);
  }
  else {
    packet_get_d_addr(payload, addr);
    country = GeoIP_country_code_by_addr(nfc->ipdb, addr);
  }
  /* Not sure if this will ever fire.. */
  if (!country)
    country = DEFAULT_COUNTRY;

  /* Fetch countries from filter */
  found = 0;
  for (i=0; i < filter->country_num; i++) {
    if (strncmp(country, filter->countries[i], 7) == 0) {
      found = 1;
      break;
    }
  }

  /* Now, we can issue the verdict */

  /* Countries acts as a whitelist */
  if (filter->verdict == NF_STOP) {
    if (found) {
      found = NF_STOP;
      nfc_stats_inc_count(globals.stats, qd->gr, country);
    }
    else
      found = NF_DROP;
  }
  /* Countries acts as a blacklist */
  else {
    if (found) {
      found = NF_DROP;
      nfc_stats_inc_count(globals.stats, qd->gr, country);
    }
    else
      found = NF_STOP;
  }

   //printf("Thread %d: packet received from group %d IP %s country %s verdict: %s\n",
   //      nfc->id, qd->gr, addr, country, found == NF_STOP ? "ACCEPT" : "DROP"); 
  
  return nfq_set_verdict(q, id, found, 0, NULL);
}

/* Destroys all the old queues and filters, re-adds them */
static int nfq_load_queues(
    nfcountry_t *nfc)
{
  int i,j;
  int nfilters = 0;
  struct qdata *qd = NULL;
  filter_t *cur;
  filter_t *new;
  filter_t *tmp = calloc(MAX_FILTERS, sizeof(filter_t));

  if (!tmp) {
    fprintf(stderr, "Thread %d unable to acquire a new filter list: %s",
            nfc->id, strerror_r(errno, nfc->errbuf, 256));
    exit(1);
  }

  /* Destroy our old filters */
  free(nfc->filters);
  nfc->filters = NULL;
  nfc->nfilters = 0;

  /* Destroy the ipdb instance and reopen */
  GeoIP_delete(nfc->ipdb);
  nfc->ipdb = GeoIP_open(globals.geoip_file, GEOIP_STANDARD|GEOIP_CHECK_CACHE);
  if (!nfc->ipdb) {
    fprintf(stderr, "Thread %d unable to open GeoIP database: %s", 
            nfc->id, strerror_r(errno, nfc->errbuf, 256));
    goto fail;
  }

  /* Destroy our old handles */
  for (i=0; i < nfc->nhandles; i++) {
    free(nfc->handles[i].qd);
    nfq_destroy_queue(nfc->handles[i].q);
  }
  nfc->nhandles = 0;
  
  for (i=0; i < globals.nfilters; i++) {
    cur = &globals.filters[i];
    for (j=cur->group_s; j <= cur->group_e; j++) {
      /* Inspect filter groups that match our id in modulo */
      if ((j % globals.ncpus) == nfc->id) {

        /* Keep a copy of the filters */
        if (nfilters >= MAX_FILTERS) {
          fprintf(stderr, "Thread %d has too many filters\n", nfc->id);
          goto fail;
        } 

        /* Assign a new filter from our blanks */
        new = &tmp[nfilters++];
        memcpy(new, cur, sizeof(filter_t));
         if (nfc->nhandles >= MAX_FILTERS) {
          fprintf(stderr, "Thread %d has too many queues\n", nfc->id);
          goto fail;
        }
        /* Assign a new queue handler */
        nfc->handles[nfc->nhandles].gr = j;
        nfc->handles[nfc->nhandles].q = nfq_handle_setup(nfc, j, &qd);
        if (!nfc->handles[nfc->nhandles].q) {
          fprintf(stderr, "Thread %d unable to register nfqueue\n", nfc->id);
          goto fail;
        }
        nfc->nhandles++;
      }
    }
  }

  /* Realloc our filters and assign to nfc */
  nfc->filters = realloc(tmp, nfilters * sizeof(filter_t));
  if (nfilters && !nfc->filters) {
    fprintf(stderr, "Thread %d unable to register filters: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    goto fail;
  }
  nfc->nfilters = nfilters;
  return 0;

fail:
  return -1;
}

/* Reloads the configuration in the thread */
static void worker_reload_config(
    int signum,
    siginfo_t *info,
    void *data)
{
  nfcountry_t *nfc = info->si_value.sival_ptr;
  if (nfq_load_queues(nfc) < 0)
    exit(EXIT_FAILURE);
}

static void * worker_thread(
    void *data)
{
  /* First we must initialize the remaining data.
   * The main thread did 'id' and 'thread' for us
   */
  int fd;
  sigset_t set;
  nfcountry_t *nfc = (nfcountry_t *)data;
  struct sigaction act;

  /* Set the signals up */
  /* to all sigs but one realtime one */
  sigfillset(&set);
  pthread_sigmask(SIG_BLOCK, &set, NULL);

  /* Setup the signal handler */
  memset(&act, 0, sizeof(act));
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = worker_reload_config;
  if (sigaction(SIGRTMIN+1, &act, NULL) < 0)
    fprintf(stderr, "Thread %d: could not setup signal handler: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
   
  memset(nfc->errbuf, 0, sizeof(nfc->errbuf));

   /* Initialize the netlink queue data */
  if ((nfc->qh = nfq_open()) == NULL) {
    fprintf(stderr, "Thread: %d could not get netlink handle: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    exit(EXIT_FAILURE);
  }
  if (nfq_bind_pf(nfc->qh, AF_INET) < 0) {
    fprintf(stderr, "Thread: %d could not bind netlink handle: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
    exit(EXIT_FAILURE);
  }
  nfc->netlinkfd = nfq_fd(nfc->qh);

  /* Its now possible to initialize our queues */
  if (nfq_load_queues(nfc) < 0)
    exit(EXIT_FAILURE);

  while(netlink_recv(nfc) >= 0);
  fprintf(stderr, "Thread: %d could not recieve from netlink: %s\n", nfc->id, strerror_r(errno, nfc->errbuf, 256));
  exit(EXIT_FAILURE);

  return NULL;
}

/* Creates all the thread structures */
static void initialize_threads(
    void)
{
  int i;
  nfcountry_t *nfc = NULL;

  nfc = calloc(globals.ncpus, sizeof(*nfc));
  if (!nfc)
    err(EXIT_FAILURE, "Could not initialize threads");

  for (i=0; i < globals.ncpus; i++) {
    nfc[i].id = i;
    nfc[i].nfilters = 0;
    if (pthread_create(&nfc[i].thread, NULL, worker_thread, &nfc[i]))
      err(EXIT_FAILURE, "Cannot initialize thread");
  }
  globals.threads = nfc;
}


/* Reloads the statistics */
static void reload_stats(
    void)
{
  filter_t *filter = NULL;
  int g,i,j;
  char *c;
  if (nfc_stats_reset(globals.stats) < 0)
    err(EXIT_FAILURE, "Cannot reset stats");
  for (i=0; i < globals.nfilters; i++) {
    filter = &globals.filters[i];
    for (j=0; j < filter->country_num; j++) {
      c = filter->countries[j];
      for (g=filter->group_s; g <= filter->group_e; g++) {
        if (!nfc_stats_add_group(globals.stats, g, c, filter->verdict))
          err(EXIT_FAILURE, "Cannot rebuild stats file");
      }
    }
  }
}

static void reload_config(
    void)
{
  /* Try to re-read filters and signal threads to apply changes */
  filter_t *filters;
  int i;
  int sz;
  union sigval sv;

  if ((sz = parse_filter_file(globals.filter_file, &filters)) < 0)
    return;
  globals.nfilters = sz;

  /* Reassign main filters */
  free(globals.filters);
  globals.filters = filters;

  /* Reload stats */
  reload_stats();

  /* Get our threads data reloaded */
  for (i=0; i < globals.ncpus; i++) {
    sv.sival_ptr = &globals.threads[i];
    pthread_sigqueue(globals.threads[i].thread, SIGRTMIN+1, sv);
  }
}

/* Main */
int main(
    int argc,
    char **argv)
{
  sigset_t set;
  int signal;
  GeoIP *gi;

  /* Block on USR1 */
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigprocmask(SIG_BLOCK, &set, NULL);

  /* Initialize */
  init_globals();

  if (argc < 4) {
    fprintf(stderr, "You must pass in a filter file, geoip database file and stats file\n");
    exit(EXIT_FAILURE);
  }

  if ((globals.nfilters = parse_filter_file(argv[1], &globals.filters)) < 0)
    exit(EXIT_FAILURE);

  globals.filter_file = strdup(argv[1]);
  if (!globals.filter_file)
    err(EXIT_FAILURE, "Cannot add filter file to config");

  globals.geoip_file = strdup(argv[2]);
  if (!globals.geoip_file)
    err(EXIT_FAILURE, "Cannot add GeoIP file to config");
  gi = GeoIP_open(globals.geoip_file, GEOIP_STANDARD|GEOIP_CHECK_CACHE);
  if (!gi)
    err(EXIT_FAILURE, "Cannot open GeoIP file");
  GeoIP_delete(gi);

  globals.stats_file = strdup(argv[3]);
  if (!globals.stats_file)
    err(EXIT_FAILURE, "Cannot initialize stats file");
  globals.stats = nfc_stats_open(globals.stats_file, NFC_STATS_CREAT);
  if (!globals.stats)
    err(EXIT_FAILURE, "Cannot open stats file");

  reload_stats();
  initialize_threads();

  /* Wait for signals */
  while (1) {
    if ((errno = sigwait(&set, &signal)))
      err(EXIT_FAILURE, "Signal waiting failed");
    switch(signal) {

    case SIGUSR1:
    reload_config();
    break;

    default:
    abort();
    break;

    }    
  }

  exit(0); 
}
