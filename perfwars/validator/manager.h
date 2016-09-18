#ifndef SERVICEMANAGER_H
#define SERVICEMANAGER_H
#include "common.h"
#include "worker.h"
#include "database.h"
#include "curve.h"
#include "ippool.h"
#include <ev.h>

#define CANCELOFF pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#define CANCELON pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)

#define NUM_WORKERS sysconf(_SC_NPROCESSORS_ONLN)
//#define NUM_WORKERS 2

typedef struct connection_stats {
  pthread_mutex_t lock;
  void *connection;
  void *round;
  void *manager;
  /* Time when connection starts */
  struct timeval init_time;
  /* Time when connection ends */
  struct timeval connect_time;
  /* Time for when SSL negotiation starts */
  struct timeval ssl_start;
  /* Time for when the SSL negotiation ends */
  struct timeval ssl_end;
  /* Time when the last byte is sent */
  struct timeval send_time;
  /* Time when the first byte arrived */
  struct timeval first_byte_time;
  /* Time when the connection is completed */
  struct timeval end_time;

  /* Finish state */
  enum {
    NOT_STARTED,
    CONNECTION_TIMED_OUT,
    CONNECTION_FAILED,
    SSL_TIMED_OUT,
    SSL_FAILED,
    SEND_TIMED_OUT,
    SEND_FAILED,
    RECV_TIMED_OUT,
    RECV_FAILED,
    VALIDATION_TIMED_OUT,
    VALIDATION_FAILED,
    SUCCESS,
  } error_code;
} connection_stats_t;


typedef struct connection {
  pthread_mutex_t lock;

  int fd;
  int no;
  void *stats;
  void *round;
  void *manager;
  void *worker;
  struct sockaddr_in6 src;
  struct sockaddr_in6 *dst;
  gnutls_session_t tls;
  ev_io io;

  off_t canvas_offset;
  size_t canvas_len;
  char *canvas_sha;
  char *canvas_filename;

  int method;
  void *resp;

  unsigned char *send_buffer;
  size_t send_buffer_len;
  off_t send_buffer_offset;

  unsigned char *recv_buffer;
  size_t recv_buffer_len;
  off_t recv_buffer_offset;
} connection_t;


typedef struct round {
  pthread_mutex_t lock;
  int worker_finished;

  void *manager;
  point_t plot;
  point_t attempt_plot;
  json_object *json;
  int concurrency;
  int attempted_concurrency;
  int actual_concurrency;

  int round_number;
  struct timeval round_start;
  struct timeval round_end;
  struct timeval attempt_end;

  float average_latency;
  float standard_deviation;

  connection_t *connections;
  connection_stats_t *stats;
} round_t;


typedef struct manager {
  pthread_cond_t manager_cond;
  pthread_cond_t worker_cond;

  char hostname[128];
  char port[48];
  char *seedname;
  int seed;
  int canvasfd;
  char *canvas;
  size_t canvas_sz;
  json_object *json;

  /* Database connection */
  db_t *db;
  /* Service curve structure */
  point_t p1, p2;
  /* Projected plot */
  service_curve_t *sc;
  /* Total time test runs for X on plot */
  int max_runtime;
  /* Maximum time a round can last for */
  int timeout;
  /* Maximum number of rounds (total /  timeout) */
  int num_rounds;
  int current_round;
  round_t *rounds;

  /* DNS IP pool of destinations */
  ippool_t *pool_dsts;
  /* IP pool of valid sources adresses */
  ippool_t *pool_srcs;

  /* Maximum number of concurrent connections */
  int max_concurrency;

  int num_workers;
  void ** workers;
  
} manager_t;

/* Function prototypes */
manager_t * manager_init(char *canvas, char *static_sums, char *host, char *port, 
                         int runtime, int timeout, int concurrency, float p1x, 
                         float p1y, float p2x, float p2y, char *seed, int workers);
void manager_destroy(manager_t *m);
int manager_run_round(manager_t *m);
const char * manager_statistics(manager_t *m);

#endif
