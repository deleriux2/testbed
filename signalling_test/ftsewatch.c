#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sysexits.h>
#include <err.h>

#include <time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>

#define PIPESZ 64*1024
#define TIMEOUT 700

/* Objectives of the test.
 * Keep reading a pipe.
 * This generates a iterator every 200ms.
 * If the pipe blocks for 600 ms it will terminate the pipe.
 */
char *companies[] = {
  "Royal Dutch Shell",
  "HSBC",
  "BP",
  "Vodafone Group",
  "GlaxoSmithKline",
  "British American Tobacco",
  "SABMiller",
  "Diageo",
  "Rio Tinto Group",
  "BHP Billiton",
  "Standard Chartered",
  "BG Group",
  "AstraZeneca",
  "Barclays",
  "Lloyds Banking Group",
  "Xstrata",
  "Unilever",
  "Reckitt Benckiser",
  "Tesco",
  "Glencore International",
  "National Grid plc",
  "Anglo American plc",
  "Prudential plc",
  "Imperial Tobacco Group",
  "BT Group",
  "Rolls-Royce Group",
  "Centrica",
  "Royal Bank of Scotland Group",
  "Compass Group",
  "Associated British Foods",
  "BSkyB",
  "SSE plc",
  "WPP plc",
  "ARM Holdings",
  "BAE Systems",
  "Shire plc",
  "Experian",
  "Tullow Oil",
  "CRH plc",
  "Fresnillo plc",
  "Antofagasta",
  "Aviva",
  "Old Mutual",
  "Pearson plc",
  "Legal & General",
  "Wolseley plc",
  "Reed Elsevier",
  "Standard Life",
  "Next plc",
  "Kingfisher plc",
  "Land Securities Group",
  "Morrison Supermarkets",
  "J Sainsbury plc",
  "Smith & Nephew",
  "Burberry Group",
  "Marks & Spencer Group",
  "Capita Group",
  "InterContinental Hotels Group",
  "Intertek Group",
  "Schroders",
  "British Land Co",
  "Petrofac",
  "United Utilities",
  "Smiths Group",
  "Weir Group",
  "Aberdeen Asset Management",
  "Randgold Resources",
  "Johnson Matthey",
  "ITV",
  "Aggreko",
  "Carnival plc",
  "Whitbread",
  "International Consolidated Airlines Group SA",
  "GKN",
  "Eurasian Natural Resources",
  "Bunzl",
  "Sage Group",
  "RSA Insurance Group",
  "G4S",
  "Hargreaves Lansdown",
  "Rexam",
  "IMI plc",
  "Babcock International",
  "Tate & Lyle",
  "Severn Trent",
  "Polymetal International",
  "Hammerson",
  "Resolution plc",
  "Meggitt",
  "Croda International",
  "TUI Travel",
  "Evraz",
  "Admiral Group",
  "AMEC",
  "Melrose plc",
  "Serco Group",
  "Vedanta Resources",
  "Wood Group",
  "Kazakhmys",
  "Intu Properties",
};

int main() {
  int poll = -1;
  int rc;
  char buf[PIPESZ];
  struct epoll_event ev;
  struct timeval t;

  memset(&ev, 0, sizeof(ev));
  memset(buf, 0 ,sizeof(buf));
  ev.events = EPOLLOUT;

  /* Setup poll */
  if ((poll = epoll_create1(0)) < 0)
    err(EX_OSERR, "Cannot setup poll");

  if (epoll_ctl(poll, EPOLL_CTL_ADD, 1, &ev) < 0)
    err(EX_OSERR, "Cannot setup poll");

  /* Change stdout to be non-blocking */
  if (fcntl(1, F_SETFD, O_NONBLOCK) < 0)
    err(EX_OSERR, "Cannot set mode on stdout");

  /* Seed our random number generator */
  srand(time(NULL));

  while(1) {
    /* Prevent candidate buffering up reads by timing out if we
     * block on writes */
    if ((rc = epoll_wait(poll, &ev, 1, TIMEOUT)) <= 0) {
      /* If interrupted continue */
      if (rc < 0 && errno == EINTR) {
        continue;
      }

      /* If there are no events, we timed out, give up */
      if (rc == 0) {
        errx(EX_SOFTWARE, "Timeout");
      }
    }
    if (ev.events & EPOLLOUT) {
      /* We null fill a very large buffer. This is a hacky workaround as only the newest
       * kernels allow us ot define the kernels buffer size */
      memset(buf, 0, sizeof(buf));
      snprintf(buf, sizeof(buf), "%d: \'%s\' %s\n", time(NULL),
               companies[rand() % 100], (rand() % 2) ? "UP" : "DOWN");
      rc = write(1, buf, sizeof(buf));
    }

    /* Give up on any odd behaviour */
    if (ev.events & EPOLLERR)
      errx(EX_OSERR, "Reader has finished");

    /* Prevent candidate predicting how often input comes in and 
     * making a heusteric step to make the report work by fluctuating
     * the sleep characteristic. */
    usleep((rand() % 500000));
  }

  return 0;
}
