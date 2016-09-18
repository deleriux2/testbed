#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <libtar.h>

#include "../validator/database.h"
#define MODE 0644

int main(
    int argc,
    char **argv)
{
  int rc;
  int canvasfd;
  int canvaslen;
  char path[4096];
  char data[MAX_FILESIZE];
  struct stat st;
  int j;
  db_record_t *rec;
  uid_t u = getuid();
  gid_t g = getgid();
  TAR *tar;

  if (argc != 3) {
    printf("Must provide canvasfile and dbfile\n");
    exit(1);
  }

  if (tar_fdopen(&tar, STDOUT_FILENO, NULL, NULL, O_WRONLY, 0000, 0) < 0)
    err(EXIT_FAILURE, "Cannot initiate tar stream");

  canvasfd = open(argv[1], O_RDONLY);
  if (canvasfd < 0)
    err(EXIT_FAILURE, "Cannot open canvas file");

  db_t *db = database_open(argv[2], DB_RDONLY);
  if (!db)
    exit(1);

  /* Find mtime */
  lstat(argv[2], &st);

  /* Iterate through each record and set files appropriately */
  for (int i=0; i < MAX_RECORDS; i++) {
    rec = &db->records[i];

    if (rec->type != TYPE_DYNAMIC)
      continue;

    memset(path, 0, sizeof(path));
    memset(data, 0, sizeof(data));
    snprintf(path, 4095, "dynamic/%s", rec->filename);
    /* user, group mode, mtime, size, finish */
    th_set_user(tar, u);
    th_set_group(tar, g);
    th_set_mode(tar, MODE);
    th_set_mtime(tar, st.st_mtime);
    th_set_size(tar, rec->len);
    th_set_path(tar, path);
    th_finish(tar);
    th_write(tar);

    if ((rc = pread(canvasfd, data, rec->len, rec->offset)) < 0) {
      warn("Cannot read canvas file");
      goto fail;
    }
    if (rc != rec->len)
      warnx("Cannot read canvas file");

    for (j=0; j < rec->len; j+=T_BLOCKSIZE) {
      if (tar_block_write(tar, &data[j]) < 0) {
        warn("Cannot write to tar file");
        goto fail;
      }
    }
  }

  tar_append_eof(tar);
  tar_close(tar);
  close(canvasfd);
  database_close(db);
  exit(0);

fail:
  warnx("Error writing tarball");

  if (tar)
    tar_close(tar);
  if (db)
    database_close(db);
  close(canvasfd);
  exit(1);
}
