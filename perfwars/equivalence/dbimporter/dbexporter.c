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
  db_t *db;
  char *dbfile;
  char *fname;
  db_record_t *rec;

  if (argc < 3) {
    fprintf(stderr, "Database exporter. Give a database name and filename and it will spit out the file\n");
    errx(EXIT_FAILURE, "Must pass a path to the database and the name of the file to query");
  }

  dbfile = argv[1];
  fname = argv[2];

  db = database_open(dbfile, DB_RDONLY);
  rec = database_get_file(db, fname);
  if (rec) {
    printf("%s", rec->data);
  }

  database_close(db);
  exit(0);
}
