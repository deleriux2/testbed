#ifndef _DATABASE_H
#define _DATABASE_H
#include "common.h"

#define TYPE_UNUSED  0
#define TYPE_DYNAMIC 1
#define TYPE_STATIC  2

#define MAX_RECORDS 50000
#define HASH_FACTOR 5
#define BITMAP_SZ (((MAX_RECORDS * HASH_FACTOR) / 64) +1)

#define DB_MAGIC 0x1a1b1c1d1e1f2021

#define DB_RDONLY 0x0
#define DB_RDWR   0x1
#define DB_CREAT  0x2

#define MIN_FILESIZE 5*1024
#define MAX_FILESIZE 50*1024

typedef struct hash_record {
  void *key;
  int keylen;
  uint64_t record_no;
  struct hash_record *next;
} hash_record_t;

typedef struct db_record {
  uint8_t type;
  uint8_t sha[32];
  unsigned char filename[48];
  off_t offset;
  size_t len;
} db_record_t;

typedef struct db_hdr {
  uint64_t magic;
  pid_t last_pid;
  uint64_t next_record_no;
} db_hdr_t;

typedef struct db {
  char *filename;
  int fd;
  int sz;
  void *map;
  db_hdr_t *hdr;
  db_record_t *records;

  pthread_mutex_t record_lock;

  pthread_mutex_t lock;
  pthread_cond_t cond;

  hash_record_t *file_buckets[MAX_RECORDS * HASH_FACTOR];
  uint64_t files_bitmap[BITMAP_SZ];
  hash_record_t *sum_buckets[MAX_RECORDS * HASH_FACTOR];
  uint64_t sums_bitmap[BITMAP_SZ];
} db_t;

db_t * database_open(char *filename, int flags);
void database_close(db_t *db);

int database_insert(db_t *db, char *filename, char sha[32], off_t offset, size_t len, char type);
db_record_t * database_get_file(db_t *db, char *filename);
db_record_t * database_get_sum(db_t *db, char *sum);
db_record_t * database_get_random(db_t *db, int *seed);
int database_import_static_checksums(db_t *db, char *filename);
void database_record_free(db_record_t *rec);

#endif
