#include "common.h"
#include "manager.h"
#include "connection.h"
#include "statistics.h"

#include <ev.h>
#include <netdb.h>
#include <math.h>

#define START_ROUND 1
#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U

static inline uint32_t HASH(
    const void *t,
    int len)
{
  const char *s = t;
  uint32_t hash = FNV_OFFSET_32;
  for(int i=0; i < len; i++) {
    hash = hash ^ (s[i]);
    hash = hash * FNV_PRIME_32;
  }
  return hash;
}

static void round_init(
    round_t *r,
    manager_t *m,
    int roundno)
{
  float tm;

  pthread_mutex_init(&r->lock, NULL);
  r->manager = m;
  r->round_number = roundno;
  r->round_start.tv_sec = 0; r->round_start.tv_usec = 0;
  r->round_end.tv_sec = 0; r->round_end.tv_usec =0;
  r->average_latency = 0.0;
  r->standard_deviation = 0.0;

  tm = (float)(roundno * m->timeout) / (float)m->max_runtime;
  tm /= 1000000;
  servicecurve_time(&r->plot, m->sc, tm);
  r->plot.x *= m->max_runtime;
  r->plot.y *= m->max_concurrency;
  r->concurrency = (int)(round(r->plot.y));
  r->worker_finished = m->num_workers;

  r->json = json_object_new_object();

  /* Connection stats go here */
  r->stats = calloc(r->concurrency, sizeof(connection_stats_t));
  if (!r->stats)
    err(EXIT_FAILURE, "Cannot allocate memory for stats in round %d", roundno);
  for (int i=0; i < r->concurrency; i++) {
    pthread_mutex_init(&r->stats[i].lock, NULL);
    r->stats[i].round = r;
    r->stats[i].manager = m;
  }

  /* Connections go here */
  r->connections = calloc(r->concurrency, sizeof(connection_t));
  if (!r->connections)
    err(EXIT_FAILURE, "Cannot allocate memory for connection in round %d", 
          roundno);
  for (int i=0; i < r->concurrency; i++) {
    pthread_mutex_init(&r->connections[i].lock, NULL);
    r->connections[i].fd = -1;
    r->connections[i].stats = &r->stats[i];
    r->stats[i].connection = &r->connections[i];
    r->connections[i].round = r;
    r->connections[i].manager = m;
    r->connections[i].canvas_offset = 0;
    r->connections[i].canvas_len = 0;
    r->connections[i].canvas_sha = NULL;
    r->connections[i].canvas_filename = NULL;
    r->connections[i].method = -1;
    r->connections[i].resp = NULL;
    r->connections[i].no = i;
  }
}


static void round_destroy(
    round_t *r)
{
  pthread_mutex_destroy(&r->lock);
}

manager_t * manager_init(
    char *canvas_name,
    char *static_sums,
    char *hostname,
    char *port,
    int runtime,
    int timeout,
    int concurrency,
    float p1x,
    float p1y,
    float p2x,
    float p2y,
    char * seed,
    int workers)
{
  int rc;
  char buf[128];
  memset(buf, 0, 128);

  manager_t *m = malloc(sizeof(*m));
  if (m == NULL)
    goto fail;
  memset(m, 0, sizeof(manager_t));

  m->pool_srcs = ippool_init_src(hostname, port);
  if (!m->pool_srcs)
    goto fail;

  m->pool_dsts = ippool_init_dst(hostname, port);
  if (!m->pool_dsts)
    goto fail;

  m->canvasfd = open(canvas_name, O_RDONLY);
  if (m->canvasfd < 0) {
    warn("Cannot open canvas file");
    goto fail;
  }
  m->canvas_sz = lseek(m->canvasfd, 0, SEEK_END);
  lseek(m->canvasfd, 0, SEEK_SET);
  m->canvas = mmap(NULL, m->canvas_sz, PROT_READ, MAP_SHARED, m->canvasfd, 0);
  if (m->canvas == MAP_FAILED) {
    warn("Cannot map canvas file");
    goto fail;
  }

  strncpy(m->hostname, hostname, 127);
  strncpy(m->port, port, 47);

  m->p1.x = p1x;
  m->p1.y = p1y;
  m->p2.x = p2x;
  m->p2.y = p2y;
  m->sc = servicecurve_init(p1x, p1y, p2x, p2y);
  if (!m->sc)
    goto fail;

  m->seedname = strdup(seed);
  m->seed = HASH(seed, strlen(seed));
  rand_r(&m->seed);

  m->max_runtime = runtime;
  m->timeout = timeout;
  m->num_rounds = runtime / ((float)timeout/1000000);
  m->current_round = START_ROUND;
  m->max_concurrency = concurrency;

  m->json = json_object_new_object();

  if (workers <= 0)
    m->num_workers = NUM_WORKERS;
  else
    m->num_workers = workers;

  m->rounds = calloc(m->num_rounds+1, sizeof(round_t));
  if (!m->rounds)
    goto fail;

  for (int i=0; i <= m->num_rounds; i++)
    round_init(&m->rounds[i], m, i);

  pthread_cond_init(&m->manager_cond, NULL);
  pthread_cond_init(&m->worker_cond, NULL);

  /* Initialize workers */
  m->workers = calloc(m->num_workers, sizeof(int*));
  if (!m->workers)
    err(EXIT_FAILURE, "Cannot initialize workers");

  for (int i=0; i < m->num_workers; i++) {
    m->workers[i] = worker_spawn(m, i, &m->seed);
    if (m->workers[i] == NULL)
      err(EXIT_FAILURE, "Cannot initialize workers");
  }

  snprintf(buf, 127, "db_%s.pws", hostname);
  m->db = database_open(buf, DB_CREAT|DB_RDWR);
  if (!m->db)
    goto fail;
  if (static_sums) {
    if (access(static_sums, R_OK) < 0)
      err(EXIT_FAILURE, "Cannot access checksum file");
    rc = database_import_static_checksums(m->db, static_sums);
    if (rc < 0)
      goto fail;
  }
  else {
    if (m->db->hdr->next_record_no == 0) {
      warnx("There are no records in the database to use as a validation");
      goto fail;
    }
  }
  return m;

fail:
  if (m && m->rounds) {
    for (int i=0; i < m->num_rounds; i++)
      round_destroy(&m->rounds[i]);
  }
  if (m && m->sc)
    servicecurve_destroy(m->sc);
  if (m) {
    if (m->pool_dsts)
      ippool_destroy(m->pool_dsts);
    if (m->pool_srcs)
      ippool_destroy(m->pool_srcs);
    if (m->canvas_sz)
      munmap(m->canvas, m->canvas_sz);
    if (m->canvasfd)
      close(m->canvasfd);  
    if (m->db)
      database_close(m->db);
    if (m->seedname)
      free(m->seedname);
    if (m->json)
      json_object_put(m->json);
    pthread_cond_destroy(&m->manager_cond);
    pthread_cond_destroy(&m->worker_cond);
    free(m);
  }
  return NULL;
}


int manager_run_round(
    manager_t *m)
{
  round_t *r = &m->rounds[m->current_round];
  worker_t *w;
  connection_t *c;
  connection_stats_t *s;
  int sleepadjust=0;

  pthread_mutex_lock(&r->lock);
  /* This waits for the preparation of workers to have completed */
  while (r->worker_finished) 
    pthread_cond_wait(&m->manager_cond, &r->lock);
  r->worker_finished = m->num_workers;
  pthread_mutex_unlock(&r->lock);

  gettimeofday(&r->round_start, NULL);
  /* Signal threads to begin */
  pthread_cond_broadcast(&m->worker_cond);

  /* Sleep the agreed timeout period */
  /* This is adjusted to take into account bandwidth link limitations
   * the link speed considered fair and the average filesize of files
   * which was determined sampling 40000 dynamically generated files */
  if (r->concurrency) {
    sleepadjust = r->concurrency / (LINK_SPEED / (AVERAGE_FILESIZE*8));
    if (sleepadjust == 0)
      sleepadjust = 1;
    sleepadjust *= 1000000;
    usleep(sleepadjust + m->timeout);
  }
  /* Signal all the threads times up */
  for (int i=0; i < m->num_workers; i++) {
    w = m->workers[i];
    ev_async_send(w->loop, &w->finish);
  }

  /* Wait for threads to declare safety */
  pthread_mutex_lock(&r->lock);
  while (r->worker_finished)
    pthread_cond_wait(&m->manager_cond, &r->lock);
  r->worker_finished = m->num_workers;
  pthread_mutex_unlock(&r->lock);

  /* Fixup the stats if necessary */
  if (r->round_end.tv_sec == 0)
    gettimeofday(&r->round_end, NULL);

  statistics_json_round(r);

  /* Clear off old connections */
  for (int i=0; i < r->concurrency; i++) {
    c = &r->connections[i];
    w = c->worker;
    connection_disconnect(w, c);
    connection_clear_buffers(c);
  }

  /* We can then allow moving onto the next round */
  m->current_round++;
  pthread_cond_broadcast(&m->worker_cond);

  /* If we hit the final round we can signal the caller
   * that there is no more work to do */
  if (m->current_round > m->num_rounds)
    return 0;
  else
    return 1;
}

const char * manager_statistics(
    manager_t *m)
{
  return statistics_json_manager(m);
}
