#ifndef _CURVE_H
#define _CURVE_H

struct _point {
  float x;
  float y;
};

typedef struct service_curve {
  struct _point p0;
  struct _point p1;
  struct _point p2;
  struct _point p3;
} service_curve_t;

typedef struct _point point_t;

service_curve_t * servicecurve_init(float p1x, float p1y, float p2x, float p2y);
void servicecurve_plot(struct _point *p, service_curve_t *sc, float tm);
void servicecurve_time(struct _point *p, service_curve_t *sc, float tm);
void servicecurve_destroy(service_curve_t *sc);

#endif
