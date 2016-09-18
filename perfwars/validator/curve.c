#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <err.h>
#include "curve.h"

#define ROOT_MAX_ITERATIONS 50
/* This only works reliably against a finite field. That is,
 * p0 and p3 are {0,0} and {1,1} respectively.
 * Which happens to be just fine in our case */
void servicecurve_time(
    struct _point *dst,
    service_curve_t *sc,
    float t)
{
  int i;
  float a = 0.0;
  float b = 1.0;
  float c;
  float x;
  struct _point p;

  for (i=0; i < ROOT_MAX_ITERATIONS; i++) {
    c = (a + b) / 2;
    servicecurve_plot(&p, sc, c);
    x = p.x;

    if (x < t)
      a = c;
    else
      b = c;
//    printf("t: %f, x: %f roundf x: %f traised %f\n", t, x, roundf(x * 100000000), t*100000000);
    if (roundf(x * 10000) == roundf(t * 10000))
      break;
  }

  if (i >= ROOT_MAX_ITERATIONS)
    errx(EXIT_FAILURE, "Cannot derive root for curve!");

  /* Now, get Y */
  servicecurve_plot(&p, sc, c);
  dst->x = t;
  dst->y = p.y;
  return;
}

#undef ROOT_MAX_INTERATIONS

void servicecurve_plot(
    struct _point *dst,
    service_curve_t *sc,
    float tm)
{
  /* This is the generic cubic polynomial formula to generate 
   * a bezier curve. Welcome to pain. */
  dst->x = pow(1 - tm, 3) * sc->p0.x 
           + 3.0 * pow(1.0 - tm, 2.0) * tm * sc->p1.x 
           + 3.0 * (1 - tm) * pow(tm, 2) * sc->p2.x 
           + pow(tm, 3) * sc->p3.x;

  dst->y = pow(1 - tm, 3) * sc->p0.y 
           + 3.0 * pow(1.0 - tm, 2.0) * tm * sc->p1.y 
           + 3.0 * (1 - tm) * pow(tm, 2) * sc->p2.y 
           + pow(tm, 3) * sc->p3.y;
  return;
}

service_curve_t * servicecurve_init(
    float p1x,
    float p1y,
    float p2x,
    float p2y)
{
  service_curve_t *sc = NULL;

  if (p1x < 0. || p1y < 0. || p2x < 0. || p2y < 0.)
    return NULL;
  if (p1x > 1. || p1y > 1. || p2x > 1. || p2y > 1.)
    return NULL;

  sc = malloc(sizeof(*sc));
  if (sc == NULL)
    return NULL;

  /* The endpoints are always static */
  sc->p0.x = 0; sc->p0.y = 0;
  sc->p3.x = 1; sc->p3.y = 1;

  /* Assign the two other points */
  sc->p1.x = p1x; sc->p1.y = p1y;
  sc->p2.x = p2x; sc->p2.y =  p2y;
  return sc;
}

void servicecurve_destroy(
   service_curve_t *sc)
{
  if (!sc)
    return;
  free(sc);
}

/*
int main() {
  float x,y;
  struct _point p;

  service_curve_t *sc = servicecurve_init(0.25, 0.0, 0.5, 1.0);
  if (!sc)
    exit(1);

  for (int i=1; i <= 3000; i++) {
    x = (float)i / 3000;
    y = servicecurve_time(sc, x);
    servicecurve_plot(&p, sc, x);
    printf("%0f %.0f\n", p.x*3000, p.y*3000);
  }
}
*/
