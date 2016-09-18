#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <cap-ng.h>
#include <sys/time.h>

#include <GeoIP.h>

#include "queue.h"
#include "event.h"

#define MAX_COUNTRIES 256
#define MAX_FILTERS   4096
#define QUEUE_SIZE    32000
#define MAX_PACKETS   1048576
#define BUFSZ         1048576
#define DIR_SRC 0
#define DIR_DST 1

static pthread_rwlock_t filterlock = PTHREAD_RWLOCK_INITIALIZER;
int load_filters(void);

struct filter {
  unsigned short *group;
  unsigned int direction;
  unsigned int verdict;
  struct nfq_q_handle *qh;
  int country_num;
  char countries[MAX_COUNTRIES][3];
};

struct queue_data {
  struct nfq_q_handle *qh;
  unsigned short groupnum;
  int id;
  char *buf;
  int buflen;
};

/* Globals */

struct config {
  char *geoip_file;
  GeoIP *gi;
  char *filterfile;
  struct filter *filters;
  int numfilters;
} config;

struct global {
  struct nfq_handle *handle;
  pthread_rwlock_t lock;
  queue_t queue;
} g;


static int packet_get_s_addr(
    char *buf,
    char addr[INET_ADDRSTRLEN])
{
  if (inet_ntop(AF_INET, &buf[12], addr, INET_ADDRSTRLEN) == NULL) {
    warnx("Could not obtain source addres for packet");
    return -1;
  }

  return 0;
}


static int packet_get_d_addr(
    char *buf,
    char addr[INET_ADDRSTRLEN])
{
  if (inet_ntop(AF_INET, &buf[16], addr, INET_ADDRSTRLEN) == NULL) {
    warnx("Could not obtain destination addres for packet");
    return -1;
  }

  return 0;
}


/* Simple function, confirms received handle is still valid
 * since it can be destroyed by a config reload */
static inline int handle_valid(
  struct nfq_q_handle *qh)
{
  int i;
  for (i=0; i < config.numfilters; i++) {
    if (config.filters[i].qh == qh)
      return 1;
  }
  return 0;
}

int parse_filter_file(
    const char *filterfile,
    struct filter **filter_result)
{
  FILE *filters = NULL;
  struct filter *filt = NULL;
  int i,j;
  int filtnum=0;
  int lineno = 0;
  char line[2048];
  unsigned short group;
  char direction[5];
  char country[512];
  char verdict[32];
  char *l, *p;

  filt = calloc(MAX_FILTERS, sizeof(struct filter));
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
    if (strlen(line) == 0)
      break;

    /* Skip comments */
    if (line[0] == '#')
      continue;
    if (sscanf(line, "%hd %s %s %s\n", &group, direction, country, verdict) != 4) {
      warnx("Cannot parse line %d in filter file %s", lineno, filterfile);
      goto fail;
    }

    /* Group parse */
    if (group < 0) {
      warnx("Cannot parse line %d in filter file %s: group must be between 0 and 65535");
      goto fail;
    }
    /* Check that the group is not already in the list */
    for (i=0; i < filtnum; i++) {
      if (*filt[i].group == group) {
        warnx("Cannot parse line %d in filter file %s: group must be unique in the file.");
        goto fail;
      }
    }
    filt[filtnum].group = malloc(sizeof(filt[filtnum].group));
    if (!filt[filtnum].group) {
      warnx("Cannot find memory for filters");
      goto fail;
    }
    *filt[filtnum].group = group;
   
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
      if (strlen(l) != 2) {
        warnx("Cannot parse line %d in filter file %s: countries codes must be 2 characters but '%s' is not", lineno, filterfile, l);
        filtnum++;
        goto fail;
      }
      strncpy(filt[filtnum].countries[filt[filtnum].country_num++], l, 2);
    }

    /* Verdict parse */
    if (strcmp(verdict, "ACCEPT") == 0) {
      filt[filtnum].verdict = NF_ACCEPT;
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
    for (i=0; i < filtnum; i++)
      free(filt[i].group);
    free(filt);
  }
  return -1;
}


int queue_push(
    struct nfq_q_handle *group,
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfdata,
    void *udata)
{
  unsigned char *buf1 = alloca(1500);
  struct nfqnl_msg_packet_hdr *ph;
  struct queue_data *qd = NULL;
  int buflen = 0;
  queue_t queue = g.queue;
  unsigned short *groupnum = (unsigned short *)udata;

  /* Obtain the packet data */ 	
  buflen = nfq_get_payload(nfdata, &buf1);
  if ((qd = malloc(sizeof(*qd))) == NULL) {
    warn("Cannot allocate memory for queue buf");
    goto fail;
  }

  ph = nfq_get_msg_packet_hdr(nfdata);
  if (ph)
    qd->id = ntohl(ph->packet_id);
  else
    qd->id = 0;

  qd->qh = group;
  qd->buflen = buflen;
  qd->buf = NULL;
  qd->groupnum = *groupnum;

  if ((qd->buf = malloc(qd->buflen)) == NULL) {
    warn("Cannot allocate memory for queue buf data");
    goto fail;
  }
  memcpy(qd->buf, buf1, qd->buflen);
  
  /* Push into queue */
  queue_put(queue, qd);
  return 1;

fail:
  if (qd && qd->buf)
    free(qd->buf);
  if (qd)
    free(qd);
  return 0;
}


/* Handle the packets coming in */
void * handle_packets(
  void *data)
{
  queue_t queue = (queue_t)data;
  struct queue_data *qd;
  struct nfqnl_msg_packet_hdr *ph;
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  struct filter *filter = NULL;
  int id = 0;
  int i,j, rc=0;
  const char *country;

  memset(saddr, 0, INET_ADDRSTRLEN);
  memset(daddr, 0, INET_ADDRSTRLEN);

  while (1) {
    qd = queue_get(queue);
    if (qd) {

      pthread_rwlock_rdlock(&g.lock);
      if (handle_valid(qd->qh)) {
        for (i=0; i < config.numfilters; i++) {
          filter = &config.filters[i];
          /* Find the matching group */
          if (qd->groupnum == *filter->group) {
            /* Fetch the direction */
            if (filter->direction == DIR_SRC) {
              packet_get_s_addr(qd->buf, saddr);
              country = GeoIP_country_code_by_addr(config.gi, saddr);
            }
            else {
              packet_get_d_addr(qd->buf, daddr);
              country = GeoIP_country_code_by_addr(config.gi, daddr);
            }
            if (!country)
              goto end;
            /* If verdict is accept, act as a whitelist */
            if (filter->verdict == NF_ACCEPT) {
              for (j=0; j < filter->country_num; j++) {
                if (strncmp(country, filter->countries[j], 2) == 0) {
                  rc = nfq_set_verdict(qd->qh, id, NF_ACCEPT, 0, NULL);
                  printf("Matched whitelist NF_ACCEPT verdict for country id %d %s\n", qd->id, country);
                  goto end;
                }
              }
              rc = nfq_set_verdict(qd->qh, id, NF_DROP, 0, NULL);
              printf("Matched whitelist NF_DROP verdict for country %d %s\n", qd->id, country);
              goto end;
            }
            /* Otherwise, act as a blacklist */
            else {
              for (j=0; j < filter->country_num; j++) {
                if (strncmp(country, filter->countries[j], 2) == 0) {
                  rc = nfq_set_verdict(qd->qh, id, NF_DROP, 0, NULL);
                  printf("Matched blacklist NF_DROP verdict for country %d %s\n", qd->id, country);
                  goto end;
                }
              }
              rc = nfq_set_verdict(qd->qh, id, NF_ACCEPT, 0, NULL);
              printf("Matched blacklist NF_ACCEPT verdict for country rc=%d, %d %s\n", rc, qd->id, country);
              goto end;
            }
          }
        }
      }
    }

end:
    pthread_rwlock_unlock(&g.lock);
    free(qd->buf);
    free(qd);
    continue;
  }
}

/* Spawn threads */
int spawn_threads(
    queue_t queue)
{
  int i, rc;
  int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
  pthread_t thread;

  for (i=0; i < ncpus; i++) {
    if ((rc = pthread_create(&thread, NULL, handle_packets, (void *)queue))) {
      errno = rc;
      warn("Cannot create thread");
      exit(EX_OSERR);
    }
    if ((rc = pthread_detach(thread))) {
      errno = rc;
      warn("Could not detach thread");
      exit(EX_OSERR);
    }
  }
  return ncpus;
}

int nfcountry_recv(
    int fd,
    int event,
    void *data)
{
  int sz;
  char buf[BUFSZ];
  struct nfq_handle *handle = data;

  if (event & EPOLLIN) {
    sz = recv(fd, buf, BUFSZ, 0);
    if (sz < 0 && errno == EINTR)
      return 0;
    else if (sz < 0)
      return -1;

    nfq_handle_packet(handle, buf, sz);
  }

  return 0;
}

/* Set up a group if one is required */
static struct nfq_q_handle * setup_nfq_handle(
    unsigned short *groupnum)
{
  struct nfq_q_handle *qh = NULL;
  /* Setup groups, since groupnum is heap allocated its safe to push it as userdata */
  if ((qh = nfq_create_queue(g.handle, *groupnum, &queue_push, (void *)groupnum)) == NULL) {
    warn("Could not bind to group");
    goto fail;
  }

  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0x0080) < 0) {
    warn("Could not set group mode");
    goto fail;
  }
  if (nfq_set_queue_maxlen(qh, MAX_PACKETS) < 0) {
    warn("Could not set group buffer size");
    goto fail;
  }

  return qh;

fail:
  if (qh)
    nfq_destroy_queue(qh);
  return NULL;
}

/* Sets up the main handler */
void setup_nfqueue_loop(
    void)
{
  int sz;
  int fd = -1;
  /* Setup handle */

  if ((g.handle = nfq_open()) == NULL){
    warn("Could not get netlink handle");
    exit(EX_OSERR);
  }

  if (nfq_bind_pf(g.handle, AF_INET) < 0) {
    warn("Could not bind netlink handle");
    exit(EX_OSERR);
  }

  fd = nfq_fd(g.handle);

  /* Event add */
  if (event_add_fd(fd, nfcountry_recv, NULL, g.handle, EPOLLIN) < 0) {
    warn("Could not add to event queue");
    exit(EX_OSERR);
  }
}


void set_process_capabilities(
    void)
{
  if (capng_get_caps_process() < 0)
    warn("Cannot retrieve processes capabilities");

  if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
    capng_clear(CAPNG_SELECT_BOTH);
    if (capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_BOUNDING_SET, CAP_NET_ADMIN) < 0) {
      warn("Cannot update capabilities");
      exit(EX_OSERR);
    }
    if (capng_apply(CAPNG_SELECT_BOTH) < 0) {
      warn("Cannot update capabilities");
      exit(EX_OSERR);
    }
  }
  else {
     warnx("Cannot set own capabilities");
  }
}

/* Attempt to safely reload the queue based off of the new filters */
static int reload_netfilter_queue(
    struct filter *filters,
    int sz)
{
  struct filter *old = NULL;
  struct filter *new = NULL;
  int i,j;
  int found = 0;
  int todelete = 0;
  struct filter *rems[MAX_FILTERS];

  /* We reload the geoip db whilst we are here too, silently ignore this if it 
   * does not function */
  GeoIP *gi = GeoIP_open(config.geoip_file, GEOIP_STANDARD|GEOIP_MMAP_CACHE);


  memset(rems, 0, sizeof(struct nfq_q_hander *) * MAX_FILTERS);

  /* Copy any matching queue that exist already into the new filters */
  for (i=0; i < config.numfilters; i++) {
    found = 0;
    old = &config.filters[i];
    for (j=0; j < sz; j++) {
      new = &filters[j];
      if (*old->group == *new->group) {
        /* Free the new->group and replace with old->group */
        free(new->group);
        new->group = old->group;
        new->qh = old->qh;
        found = 1;
        break;
      }
    }
    /* If the old queue is not found, we must remove it */
    if (!found) {
      /* Assign for deletion */
      rems[todelete++] = old;
    }
  }

  /* Now, for any queue without a queue handler, create it */
  for (i=0; i < sz; i++) {
    new = &filters[i];
    if (new->qh == NULL) {
      new->qh = setup_nfq_handle(new->group);
      if (!new->qh)
        goto fail;
    }
  }

  pthread_rwlock_wrlock(&g.lock);
  /* Switch old geoip db for new */
  if (gi) {
    GeoIP_delete(config.gi);
    config.gi = gi;
  }

  /* Remove those old handles we marked for deletion */
  for (i=0; i < todelete; i++) {
    free(rems[i]->group);
    nfq_destroy_queue(rems[i]->qh);
  }

  /* Remove the old config (no q handlers or groups removed, 
   * as already destroyed or handled) */
  free(config.filters);
  /* Swap the config for the new one */
  config.filters = filters;
  config.numfilters = sz;

  pthread_rwlock_unlock(&g.lock);
  return 1;

fail:
  pthread_rwlock_unlock(&g.lock);
  /* Destroy any queue not from the old config */
  for (i=0; i < sz; i++) {
    found = 0;
    new = &filters[i];
    for (j=0; j < config.numfilters; j++) {
      old = &config.filters[j];
      if (new->qh && new->qh == old->qh) {
        found = 1;
        break;
      }
    }
    if (!found) {
      free(new->group);
      nfq_destroy_queue(new->qh);
    }
  }
  return 0;
}

void reload_config(
    int sig)
{
  int sz;
  struct filter *filters;
  if ((sz = parse_filter_file(config.filterfile, &filters)) < 0) {
    warnx("Unable to reload config file");
    return;
  }
  if (!reload_netfilter_queue(filters, sz)) {
    warnx("Unable to reload queues in config file");
    free(filters);
   return;
  }
  warnx("Reloaded configuration");
}

int main(
    int argc,
    char **argv)
{
  int groupnum = 0;
  int nlfd = -1;
  struct sigaction act;
  struct filter *filters;
  int sz;

  memset(&act, 0, sizeof(act));
  memset(&config, 0, sizeof(config));

  set_process_capabilities();

  if (argc < 3) {
    warnx("Must pass path to the geoip database and filter file");
    exit(EX_SOFTWARE);
  }

  /* Next arg is path to GeoIP database, bit redundant to do this here
   * but it will error at this point if something is obviously wrong */
  config.geoip_file = strdup(argv[1]);
  config.gi = GeoIP_open(config.geoip_file, GEOIP_STANDARD|GEOIP_MMAP_CACHE);
  if (!config.gi)
    err(EXIT_FAILURE, "Cannot open GeoIP database file: %s\n", config.geoip_file);

  /* Then pass the filter file */
  config.filterfile = strdup(argv[2]);
  if (!config.filterfile)
    err(EXIT_FAILURE, "Cannot allocate memory for config");
  if ((sz = parse_filter_file(config.filterfile, &filters)) < 0)
    exit(1);

  /* Prime remaining config */
  config.numfilters = 0;
  config.filters = NULL;

  /* Create lock */
  pthread_rwlock_init(&g.lock, NULL);

  /* Configure the queue */
  g.queue = queue_init(QUEUE_SIZE);
  if (!g.queue) {
    warn("Cannot initialize the queue");
    exit(EX_OSERR);
  }

  event_init();
  setup_nfqueue_loop();

  /* Load the netfilter queues */
  reload_netfilter_queue(filters, sz);

  spawn_threads(g.queue);

  /* Setup sighandler */
  act.sa_handler = reload_config;
  if (sigaction(SIGUSR1, &act, NULL) < 0) {
    warn("Could not install signal handler");
    exit(EX_OSERR);
  }

  while (event_loop(5, -1) > 0);

  exit(0);
}
