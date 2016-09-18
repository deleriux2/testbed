#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

void *dowait(void *data)
{
  sleep(59);
  return;
}

int main() {
  pthread_t thread;
  pthread_create(&thread, NULL, dowait, NULL);
  pthread_join(thread, NULL);
}
