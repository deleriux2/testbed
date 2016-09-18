#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include "bbdb.h"

int main (
   int argc,
   const char **argv)
{
  enum verdict v;
  char *nm;
  bbdb_t *bbdb = NULL;

  bbdb = bbdb_new("test.bbd");
  if (!bbdb)
    err(EXIT_FAILURE, "error");

  v = bbdb_insert(bbdb, "192.168.1.1", DROP);
  printf("v: %d\n", v);
  v = bbdb_insert(bbdb, "192.168.1.1", ALLOW);
  printf("v: %d\n", v);

  bbdb_add_name(bbdb, "test_name");
  printf("Number of names: %d\n", bbdb_get_num_names(bbdb));
  nm = bbdb_get_name(bbdb, 0);
  printf("Name 1: %s\n", nm);
  free(nm);

  bbdb_seal(bbdb, "key.pem", "root.der");

  v = bbdb_verdict(bbdb, "192.168.1.1");
  printf("v: %d\n", v);
  bbdb_close(bbdb);
}
