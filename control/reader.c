#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>

#define LINECOUNT 2048
#define BUFSZ 24

void readfile(
  const char *filename)
{
  char buf[BUFSZ];
  char oldbuf[BUFSZ];
  char expect[BUFSZ];
  FILE *file = NULL;
  int linecount = 0;
  int tmp;

  if ((file = fopen(filename, "r")) == NULL) {
    warn("Could not open %s", filename);
    goto fail;
  }

  /* Read the initial value into oldbuf */
  if (!fgets(oldbuf, BUFSZ, file)) {
    fprintf(stderr, "Cannot obtain initial value!\n");
    goto fail;
  }
  linecount++;

  /* Read each value in the file */
  while (fgets(buf, BUFSZ, file)) {
    if (linecount > LINECOUNT) {
      fprintf(stderr, "Expecting %d lines but got more\n", LINECOUNT);
      goto fail;
    }
    buf[strlen(buf)-1] = 0;
    if (strncmp(buf, oldbuf, BUFSZ) != 1) {
      /* Work out the next entry */
      sscanf(oldbuf, "%08d", &tmp);
      tmp++;
      snprintf(expect, BUFSZ, "%08d", tmp);
      fprintf(stderr, "Expected to get a sequentially following pattern!\n"
                       "Have:     %s\n"
                       "Expected: %s\n"
                       "Got:      %s\n",
              oldbuf, expect, buf);
      goto fail;
    }
    strncpy(oldbuf, buf, BUFSZ);
    linecount++;
  }

  if (linecount != LINECOUNT) {
    fprintf(stderr, "Expected %d lines but got %d lines\n",
            LINECOUNT, linecount);
    goto fail;
  }

  fclose(file);
  return;

fail:
  sleep(1);
  if (file)
    fclose(file);
  return;
}

int main() {
  while (1) {
   readfile("moo.txt");
  }

  return 0;
}
