#include "manager.h"
#include "statistics.h"
#include "http.h"
#include <math.h>
#include <json-c/json.h>
#include <arpa/inet.h>

static const char *method_names[] = {
  "PUT", "PUT", "GET", "SHA"
};

static const char *error_states[] = {
  "Not started",
  "Connection time out",
  "Connection failure",
  "SSL negotiation time out",
  "SSL connection failure",
  "Sending time out",
  "Sending failure",
  "Receiving timed out",
  "Receiving failure",
  "Validation timed out",
  "Validation failed",
  "Success",
};

static float mean_f(
   float *pop,
   int len)
{
  float sum=0.;
  for (int i=0; i < len; i++)
    sum += pop[i];
  return sum / len;
}

static float mean_i(
    int *pop,
    int len)
{
  float sum=0.;
  for (int i=0; i < len; i++)
    sum += pop[i];
  return sum / len;
}

static float pstdev(
    float *pop,
    int len)
{
  float *cpy = alloca(len * sizeof(float));
  int mn = mean_f(pop, len);
  float variance;

  for (int i=0; i < len; i++) {
    cpy[i] = (pop[i] - mn);
    cpy[i] *= cpy[i];
  }

  variance = mean_f(cpy, len);
  return sqrt(variance);
}

static float pythag(
    float x,
    float y)
{
  return sqrt(((x*x) + (y*y)));
}

static float timediff(
    struct timeval *n,
    struct timeval *t)
{
  float res;
  float x;
  res = n->tv_sec - t->tv_sec;
  x = n->tv_usec - t->tv_usec;
  if (x < 0) {
    res--;
    x = -x;
  }
  x /= 1000000;
  res += x;
  return res;
}

static float distance_between_points(
    point_t *a,
    point_t *b)
{
  float xdiff,ydiff;

  xdiff = b->x - a->x;
  ydiff = a->y - b->y;
  return pythag(xdiff, ydiff);
}

json_object * statistics_connection(
    connection_t *c)
{
  connection_stats_t *s = c->stats;
  json_object *job = json_object_new_object();  
  json_object *value;
  char buf[INET6_ADDRSTRLEN+1];
  int l;
  char port[16];
  char dataxfer[4096];

  /* Connection addresses */
  memset(buf, 0, sizeof(buf));
  memset(port, 0, sizeof(port));
  if (s->error_code > CONNECTION_FAILED) {
    inet_ntop(c->src.sin6_family, &c->src.sin6_addr, buf, INET6_ADDRSTRLEN); 
    strcat(buf, ":");
    snprintf(port, 16, "%hu", ntohs(c->src.sin6_port));
    strcat(buf, port);    
  }
  else
    strcat(buf, "No connection");
  value = json_object_new_string(buf);
  json_object_object_add(job, "source address", value);

  memset(buf, 0, sizeof(buf));
  memset(port, 0, sizeof(port));
  if (s->error_code > NOT_STARTED) {
    inet_ntop(c->dst->sin6_family, &c->dst->sin6_addr, buf, INET6_ADDRSTRLEN); 
    strcat(buf, ":");
    snprintf(port, 16, "%hu", ntohs(c->dst->sin6_port));
    strcat(buf, port);    
  }
  value = json_object_new_string(buf);
  json_object_object_add(job, "destination address", value);

  if (s->error_code > CONNECTION_FAILED)
    value = json_object_new_double(timediff(&s->ssl_start, &s->connect_time));
  else
    value = json_object_new_double(-1.0);
  json_object_object_add(job, "connection time", value);

  if (s->error_code > SSL_FAILED)
    value = json_object_new_double(timediff(&s->ssl_end, &s->ssl_start));
  else
    value = json_object_new_double(-1.0);
  json_object_object_add(job, "ssl negotiation time", value);

  if (s->error_code > RECV_TIMED_OUT)
    value = json_object_new_double(timediff(&s->first_byte_time, &s->send_time));
  else
    value = json_object_new_double(-1.0);
  json_object_object_add(job, "first byte time", value);

  if (s->error_code > VALIDATION_TIMED_OUT)
    value = json_object_new_double(timediff(&s->end_time, &s->first_byte_time));
  else
    value = json_object_new_double(-1.0);
  json_object_object_add(job, "transfer time", value);

  if (s->error_code >= SUCCESS)
    value = json_object_new_double(timediff(&s->end_time, &s->connect_time));
  else
    value = json_object_new_double(-1.0);
  json_object_object_add(job, "total time", value);

  value = json_object_new_string(error_states[s->error_code]);
  json_object_object_add(job, "state", value);

  memset(dataxfer, 0, sizeof(dataxfer));
  if (c->send_buffer && s->error_code < SUCCESS) {
    memset(dataxfer, 0, sizeof(dataxfer));
    l = strlen(c->send_buffer);
    if (l < 2047) 
      strncpy(dataxfer, c->send_buffer, l);
    else {
      strncpy(dataxfer, c->send_buffer, 1024);
      strcat(dataxfer, "\n....\n(data truncated)\n....\n");
      strncat(dataxfer, &c->send_buffer[l-128], 128);
    }
    value = json_object_new_string(dataxfer);
  }
  else
    value = json_object_new_string("Not applicable");
  json_object_object_add(job, "send buffer", value);

  memset(dataxfer, 0, sizeof(dataxfer));
  if (c->recv_buffer && s->error_code < SUCCESS) {
    memset(dataxfer, 0, sizeof(dataxfer));
    l = strlen(c->recv_buffer);
    if (l < 2047) 
      strncpy(dataxfer, c->recv_buffer, l);
    else {
      strncpy(dataxfer, c->recv_buffer, 1024);
      strcat(dataxfer, "\n....\n(data truncated)\n....\n");
      strncat(dataxfer, &c->recv_buffer[l-128], 128);
    }
    value = json_object_new_string(dataxfer);
  }
  else
    value = json_object_new_string("Not applicable");
  json_object_object_add(job, "receive buffer", value);


  return job;
}
/*
  pthread_mutex_t lock;

  unsigned char *send_buffer;
  size_t send_buffer_len;
  off_t send_buffer_offset;
  unsigned char *recv_buffer;
  size_t recv_buffer_len;
  off_t recv_buffer_offset;
*/

const char * statistics_json_manager(
    manager_t *m)
{
  json_object *value;
  json_object *array;
  json_object *job = m->json;
  json_object *obj;
  char buf[INET6_ADDRSTRLEN+1];

  value = json_object_new_string(m->seedname);
  json_object_object_add(job, "seed", value);
  value = json_object_new_string(m->hostname);
  json_object_object_add(job, "hostname", value);
  value = json_object_new_string(m->port);
  json_object_object_add(job, "port", value);

  obj = json_object_new_object();

  /* P0 point */
  array = json_object_new_array();
  value = json_object_new_double(0.0);
  json_object_array_add(array, value);
  json_object_array_add(array, value);
  json_object_object_add(obj, "p0", array);
  /* P1 point */
  array = json_object_new_array();
  value = json_object_new_double(m->p1.x);
  json_object_array_add(array, value);
  value = json_object_new_double(m->p1.y);
  json_object_array_add(array, value);
  json_object_object_add(obj, "p1", array);
  /* P2 point */
  array = json_object_new_array();
  value = json_object_new_double(m->p2.x);
  json_object_array_add(array, value);
  value = json_object_new_double(m->p2.y);
  json_object_array_add(array, value);
  json_object_object_add(obj, "p2", array);
  /* P3 point */
  array = json_object_new_array();
  value = json_object_new_double(1.0);
  json_object_array_add(array, value);
  json_object_array_add(array, value);
  json_object_object_add(obj, "p3", array);

  json_object_object_add(job, "service curve", obj);

  value = json_object_new_int(m->max_runtime);
  json_object_object_add(job, "runtime", value);
  value = json_object_new_int(m->timeout/1000000);
  json_object_object_add(job, "round timeout", value);
  value = json_object_new_int(m->num_workers);
  json_object_object_add(job, "number of workers", value);
  value = json_object_new_int(m->max_concurrency);
  json_object_object_add(job, "concurrency", value);

  /* IP pool sources */
  array = json_object_new_array();
  for (int i=0; i < m->pool_srcs->total; i++) {
    memset(buf, 0, sizeof(buf));
    inet_ntop(m->pool_srcs->addrs[i].sin6_family, 
              &m->pool_srcs->addrs[i].sin6_addr, buf, INET6_ADDRSTRLEN);
    value = json_object_new_string(buf);
    json_object_array_add(array, value);
  }
  json_object_object_add(job, "source addresses", array);

  /* IP pool destinations */
  array = json_object_new_array();
  for (int i=0; i < m->pool_dsts->total; i++) {
    memset(buf, 0, sizeof(buf));
    inet_ntop(m->pool_dsts->addrs[i].sin6_family, 
              &m->pool_dsts->addrs[i].sin6_addr, buf, INET6_ADDRSTRLEN);
    value = json_object_new_string(buf);
    json_object_array_add(array, value);
  }
  json_object_object_add(job, "destination addresses", array);

  /* IP pool destinations */
  array = json_object_new_array();
  for (int i=1; i <= m->num_rounds; i++) {
    json_object_array_add(array, m->rounds[i].json);
  }
  json_object_object_add(job, "rounds", array);
 
  return json_object_to_json_string_ext(job, JSON_C_TO_STRING_PRETTY);
}



void statistics_json_round(
    round_t *r)
{
  manager_t *m = r->manager;
  connection_t *c; 
  connection_stats_t *s;
  http_response_t *resp;

  float *latencies = alloca(r->concurrency * sizeof(float));
  float latency_mean;
  float latency_dev;
  float curve_offset;
  point_t realized_plot;
  point_t actual_plot;
  json_object *value;
  json_object *array;
  json_object *job = r->json;


  /* Calculate latencies */
  for (int i=0; i < r->concurrency; i++) {
    c = &r->connections[i];
    s = c->stats;
    resp = c->resp;
    latencies[i] = timediff(&s->end_time, &s->send_time);
    if (s->error_code < SUCCESS) 
      latencies[i] = (float)m->timeout/1000000;
    if (latencies[i] > (m->timeout/1000000))
      latencies[i] = (float)m->timeout/1000000;
  }
  latency_mean = mean_f(latencies, r->concurrency);
  latency_dev = pstdev(latencies, r->concurrency);

  /* Plot data */
  realized_plot.x = r->plot.x = (float)(r->round_number * 
                                ((float)m->timeout)/1000000) +
                                timediff(&r->attempt_end, &r->round_start);
  realized_plot.y = (float)r->attempted_concurrency;
  actual_plot.x = realized_plot.x + latency_mean;
  actual_plot.y = (float)r->actual_concurrency;

  curve_offset = distance_between_points(&realized_plot, &actual_plot);

  value = json_object_new_int(r->concurrency);
  json_object_object_add(job, "concurrency", value);
  value = json_object_new_int(r->attempted_concurrency);
  json_object_object_add(job, "realized concurrency", value);
  value = json_object_new_int(r->actual_concurrency);
  json_object_object_add(job, "actual concurrency", value);
  value = json_object_new_double((double)r->round_start.tv_sec + 
                                ((double)r->round_start.tv_usec / 1000000));
  json_object_object_add(job, "round start time", value);
  value = json_object_new_double((double)r->round_end.tv_sec + 
                                ((double)r->round_end.tv_usec / 1000000));
  json_object_object_add(job, "round end time", value);
  value = json_object_new_double((double)r->attempt_end.tv_sec + 
                                ((double)r->attempt_end.tv_usec / 1000000));
  json_object_object_add(job, "connection completion time", value);
  value = json_object_new_double(latency_mean);
  json_object_object_add(job, "mean latency", value);
  value = json_object_new_double(latency_dev);
  json_object_object_add(job, "population standard deviation", value);
  value = json_object_new_double(curve_offset);
  json_object_object_add(job, "distance from curve", value);

  /* Projected point on the curve */
  array = json_object_new_array();
  value = json_object_new_double(r->plot.x);
  json_object_array_add(array, value);
  value = json_object_new_double(r->plot.y);
  json_object_array_add(array, value);
  json_object_object_add(job, "projected plot", array);

  /* Realized plot on the curve */
  array = json_object_new_array();
  value = json_object_new_double(realized_plot.x);
  json_object_array_add(array, value);
  value = json_object_new_double(realized_plot.y);
  json_object_array_add(array, value);
  json_object_object_add(job, "realized plot", array);

  /* Actual plot on the curve */
  array = json_object_new_array();
  value = json_object_new_double(actual_plot.x);
  json_object_array_add(array, value);
  value = json_object_new_double(actual_plot.y);
  json_object_array_add(array, value);
  json_object_object_add(job, "actual plot", array);

  array = json_object_new_array();
  for (int i=0; i < r->concurrency; i++) {
    c = &r->connections[i];
    value = statistics_connection(c);
    json_object_array_add(array, value);
  }
  json_object_object_add(job, "connections", array);
  return;
}

void statistics_calculate(
    round_t *r)
{
  int co = r->concurrency;
  
  connection_stats_t *s;
  connection_t *c;
  manager_t *m = r->manager;
  http_response_t *resp;
  point_t realized_plot;
  point_t actual_plot;

  /* Actual stats */

  /* Realized time to end time */
  float *latencies = alloca(co * sizeof(float));
  float latency_mean;
  float latency_dev;
  int hit=0;
  int missed=0;
  float curve_offset;
  float score;
  int errcodes[12];
  int methods[4];

  memset(errcodes, 0, sizeof(errcodes));
  memset(methods, 0, sizeof(methods));
  /* Calculate latencies */
  for (int i=0; i < co; i++) {
    c = &r->connections[i];
    s = c->stats;
    resp = c->resp;
    latencies[i] = timediff(&s->end_time, &s->init_time);
    errcodes[s->error_code]++;
    if (s->error_code < SUCCESS) {
      latencies[i] = (float)m->timeout/1000000;
      missed++;
      if (s->error_code == VALIDATION_FAILED) {
        methods[c->method]++;
/*
        if (c->method == 3) {
          printf("%5d: %65s: %s --> %d\n", i, c->canvas_sha, method_names[c->method], resp->errcode);
        }
        else {
          printf("%5d: %65s: %s --> %d\n", i, c->canvas_filename, method_names[c->method], resp->errcode);
        }
*/
      }
    }
    else {
      latencies[i] = timediff(&s->end_time, &s->init_time);
      hit++;
    }
  }

  realized_plot.y = (float)r->attempted_concurrency;
  if (r->attempt_end.tv_sec == 0)
    realized_plot.x = r->plot.x;
  else
    realized_plot.x = (float)(r->round_number * ((float)m->timeout)/1000000) + 
                     timediff(&r->attempt_end, &r->round_start);
  
  latency_mean = mean_f(latencies, co);
  latency_dev = pstdev(latencies, co);

  actual_plot.y = (float)hit;
  actual_plot.x = realized_plot.x + latency_mean;

  curve_offset = distance_between_points(&realized_plot, &actual_plot);

  score = curve_offset + latency_mean + latency_dev;

  /* Print the projected plot points */
/*
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
*/
/*
  if (r->round_number == 1) 
    printf("%s %8s %8s %14s %12s %20s %12s %4s\n", "Round" "   CurveX", "CurveY", "StartTime", "Concurrency", "Latency", "Met Concurrency", "Curve Offset", "Score");
  printf("%4d %8.3f %8.3f %10.3f %12.0f %14.3f %14.0f %14.3f %8.3f %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d\n", 
         r->round_number, r->plot.x, r->plot.y, realized_plot.x, realized_plot.y,
         actual_plot.x, actual_plot.y, curve_offset, score,
         errcodes[0], errcodes[1], errcodes[2], errcodes[3], errcodes[4],
         errcodes[5], errcodes[6], errcodes[7], errcodes[8], errcodes[9],
         errcodes[10], errcodes[11], methods[0] + methods[1], methods[2],
         methods[3]);
*/
}
