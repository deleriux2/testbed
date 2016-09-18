#include "../common.h"
#include "../database.h"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <nettle/sha.h>

int main(
    int argc,
    char **argv)
{
  char *dirname;
  char *dbfile;
  DIR *d;
  int fd;
  int dfd;
  struct dirent *ent;
  char buf[DB_MAX_DATA_SIZE];
  off_t realsz;
  size_t sz;
  unsigned char shadata[32];

  struct sha256_ctx sha;

  sha256_init(&sha);

  db_t *db;

  if (argc < 3) {
    fprintf(stderr, "Database importer. Creates or updates a database file with static records using the correct key.\n");
    errx(EXIT_FAILURE, "Must pass a path to a directory and the name of the database file to create/update");
  }

  dbfile = argv[2];
  dirname = argv[1];

  db = database_open(dbfile, DB_RDWR|DB_CREAT);

  d = opendir(dirname);
  if (!d)
    err(EXIT_FAILURE, "Cannot open directory");
  dfd = dirfd(d);

  while ((ent = readdir(d)) != NULL) {
    if (ent->d_type != DT_REG)
      continue;

    fd = openat(dfd, ent->d_name, O_RDONLY);
    if (fd < 0) {
      warn("Cannot open file %s/%s", dirname, ent->d_name);
      continue;
    }

    realsz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    sz = read(fd, buf, DB_MAX_DATA_SIZE);
    if (sz < 0) {
      warn("Cannot read file %s/%s", dirname, ent->d_name);
      continue;
    }

    if (realsz != sz) {
      printf("%d/%d\n", sz, realsz);
      warnx("Skipping %s/%s as the file is larger then the max record size", 
            dirname, ent->d_name);
      continue;
    }
   
    /* Calculate shasum */
    sha256_update(&sha, SHA256_KEYLEN, SHA256_KEY);
    sha256_update(&sha, sz, buf);
    sha256_digest(&sha, 32, shadata);
    if (database_insert(db, ent->d_name, shadata, buf, sz, TYPE_STATIC) != 1)
      errx(EXIT_FAILURE, "There was a problem adding the record to the database."
           " Giving up."); 

// int database_insert(db_t *db, char *filename, char sha[32], char *data, size_t len, char type);

    close(fd);
  }

  database_close(db);
  closedir(d);

  exit(0);
}
