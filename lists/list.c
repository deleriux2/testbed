#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sysexits.h>
#include <assert.h>

#include <sys/queue.h>


LIST_HEAD(listhead, entry) head;

typedef struct entry {
  int value;
  LIST_ENTRY(entry) ent;
} entry_t;


int main(const char argc, const char **argv) {
  entry_t *ep = NULL;

  LIST_INIT(&head);

  int i;
  for (i=0; i < 1000; i++) {
    if ((ep = malloc(sizeof(entry_t))) == NULL) 
      err(EX_OSERR, "Memory allocation problem");

    ep->value = i;
    LIST_INSERT_HEAD(&head, ep, ent);
  }

  for (ep = head.lh_first; ep != NULL; ep = ep->ent.le_next) {
    printf("Value: %d\n", ep->value);
  }

  exit(0);
}

