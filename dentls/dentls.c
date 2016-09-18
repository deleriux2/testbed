/* I can be compiled with the command "gcc -o killdir killdir.c" */

/* Be careful! I'm memory hungry! */

#define _GNU_SOURCE
#include <search.h>	/* Defines tree functions */
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#ifdef THREADING
#include <pthread.h>

struct worker_args {
  char **files;
  int len;
};

static void * threaded_unlink(void *data);
static void spawn_workers(int numfiles);

volatile int totalfiles=0;
static int filesidx=0;
static int numthreads = 0;
static char **all_files;
#endif

static void spawn_workers(int numfiles) {
  pthread_t *threads = NULL;
  int i=0, offset=0, len=0;
  struct worker_args *data;
  numthreads = sysconf(_SC_NPROCESSORS_ONLN);

  threads = calloc(numthreads, sizeof(*threads));
  if (!threads) {
    perror("Cannot initialize memory");
    exit(1);
  }

  data = calloc(numthreads, sizeof(*data));
  for (i=0; i < numthreads; i++) {
    offset = i * (numfiles/numthreads);
    if ((offset+len) > numfiles) {
      len = numfiles-offset;
    }
    else {
      len = numfiles/numthreads;
    }

    data[i].files = &all_files[offset];
    data[i].len = len;
    if (pthread_create(&threads[i], NULL, threaded_unlink, (void *)&data[i] )) {
      perror("Cannot start thread\n");
      exit(1);
    }
  }

  for (i=0; i < numthreads; i++) {
    pthread_join(threads[i], NULL);
  }
}

void * threaded_unlink(void *data) {
  struct worker_args *args;
  args = (struct worker_args *)data;
  int i;

  for (i=0; i < args->len; i++) {
//    printf("Deleting: %s\n", args->files[i]);
    if (unlink(args->files[i]) < 0) {
      perror("Could not unlink file");
      fprintf(stderr, "This file: %s\n", args->files[i]);
      exit(1);
    }
  }
}

#define PLUS_PERCENT(a, b) a + ((a/100)*b)

/* Because most filesystems use btree to store dents
 * its very important to perform an in-order removal
 * of the file contents. Performing an 'as-is read' of
 * the contents causes lots of btree rebalancing
 * that has significantly negative effect on unlink performance
 */

/* Tests indicate that performing a ascending order traversal
 * is about 1/3 faster than a descending order traversal */
int compare_fnames(const void *key1, const void *key2) {
  return strcmp((char *)key1, (char *)key2);
}

void walk_tree(const void *node, VISIT val, int lvl) {
 // printf("%s\n", *(char **)node);
  switch(val) {
  case leaf:
    all_files[filesidx++] = *(char **)node;
    break;
  case endorder:
    all_files[filesidx++] = *(char **)node;
    break;
  default:
    return;
    break;
  }

}

void dummy_destroy(void *nil) {
  return;
}

void *tree = NULL;

struct linux_dirent {
        long           d_ino;
        off_t          d_off;
        unsigned short d_reclen;
        char           d_name[256];
        char           d_type;
};

int main(const int argc, const char** argv) {
    int dirfd = -1;
    int offset = 0;
    int bufcount = 0;
    void *buffer = NULL;
    char *d_type;
    struct linux_dirent *dent = NULL;
    struct stat dstat;

    /* Test we have a directory path */
    if (argc < 2) {
        fprintf(stderr, "You must supply a valid directory path.\n");
        exit(1);
    }

    const char *path = argv[1];

    /* Standard sanity checking stuff */
    if (access(path, R_OK) < 0) {
        perror("Could not access directory");
        exit(1);
    }

    if (lstat(path, &dstat) < 0) {
        perror("Unable to lstat path");
        exit(1);
    }

    if (!S_ISDIR(dstat.st_mode)) {
        fprintf(stderr, "The path %s is not a directory.\n", path);
        exit(1);
    }

    /* We need to allocate a buffer thats roughly 15% bigger than what the size shows. */
    if ((buffer = malloc(PLUS_PERCENT(dstat.st_size, 15))) == NULL) {
        perror("malloc failed");
        exit(1);
    }

    /* Open the directory */
    if ((dirfd = open(path, O_RDONLY)) < 0) {
        perror("Open error");
        exit(1);
    }

    /* Switch directories */
    fchdir(dirfd);

    while ((bufcount = syscall(SYS_getdents, dirfd, buffer, PLUS_PERCENT(dstat.st_size, 15))) >  0) {
        offset = 0;
        dent = buffer;
        while (offset < bufcount) {
            /* Dont print thisdir and parent dir */
            if (!((strcmp(".",dent->d_name) == 0) || (strcmp("..",dent->d_name) == 0))) {
                d_type = (char *)dent + dent->d_reclen-1;
                /* Only print files */
                if (*d_type == DT_REG) {
                    /* Sort all our files into a binary tree */
		    if (!tsearch(dent->d_name, &tree, compare_fnames)) {
                      fprintf(stderr, "Cannot acquire resources for tree!\n");
                      exit(1);
                    }
                    totalfiles++;
                }
            }
            offset += dent->d_reclen;
            dent = buffer + offset;
        }
    }
    printf("Total files: %d\n", totalfiles);
    all_files = calloc(totalfiles, sizeof(*all_files));
    if (!all_files) {
      perror("Memory allocation error");
      exit(1);
    }

    printf("Performing delete..\n");

    twalk(tree, walk_tree);
    printf("Done\n");

    spawn_workers(totalfiles);

    close(dirfd);
    free(buffer);
    tdestroy(tree, dummy_destroy);
}
