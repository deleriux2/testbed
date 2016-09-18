#include "common.h"
#include "manager.h"
#include "database.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>

#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U

static inline uint32_t HASH(
    const void *t,
    int len)
{
  const char *s = t;
  uint32_t hash = FNV_OFFSET_32;
  for(int i=0; i < len; i++) {
    hash = hash ^ (s[i]); 
    hash = hash * FNV_PRIME_32;
  }
  return hash % (MAX_RECORDS * HASH_FACTOR);
}

static inline void lock_files_bucket(
    db_t *db,
    int recno)
{
  int db_offset = recno / 64;
  int bit = 1 << (recno % 64);
  pthread_mutex_lock(&db->lock);
  /* Check if locked */
  while (db->files_bitmap[db_offset] & bit)
    pthread_cond_wait(&db->cond, &db->lock);
  /* Flip the bit */
  db->files_bitmap[db_offset] |= bit;
  pthread_mutex_unlock(&db->lock);
}

static inline void unlock_files_bucket(
    db_t *db,
    int recno)
{
  int db_offset = recno / 64;
  int bit = 1 << (recno % 64);
  pthread_mutex_lock(&db->lock);
  /* unflip the bit */
  db->files_bitmap[db_offset] &= ~bit;
  pthread_cond_signal(&db->cond);
  pthread_mutex_unlock(&db->lock);
}


static inline void lock_sums_bucket(
    db_t *db,
    int recno)
{
  int db_offset = recno / 64;
  int bit = 1 << (recno % 64);
  pthread_mutex_lock(&db->lock);
  /* Check if locked */
  while (db->sums_bitmap[db_offset] & bit)
    pthread_cond_wait(&db->cond, &db->lock);
  /* Flip the bit */
  db->sums_bitmap[db_offset] |= bit;
  pthread_mutex_unlock(&db->lock);
}

static inline void unlock_sums_bucket(
    db_t *db,
    int recno)
{
  int db_offset = recno / 64;
  int bit = 1 << (recno % 64);
  pthread_mutex_lock(&db->lock);
  /* unflip the bit */
  db->sums_bitmap[db_offset] &= ~bit;
  pthread_cond_signal(&db->cond);
  pthread_mutex_unlock(&db->lock);
}

static int sum_hash_search(
    db_t *db,
    const void *s,
    int len,
    int *recno)
{
  hash_record_t *hr;
  int bucket = HASH(s, len);
  hr = db->sum_buckets[bucket];
  if (hr == NULL)
    return 0;

  lock_sums_bucket(db, bucket);
  for (hr; hr != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      *recno = hr->record_no;
      unlock_sums_bucket(db, bucket);
      return 1;
    }
  }
  unlock_sums_bucket(db, bucket);
  return 0;
}


static int sum_hash_update_recno(
    db_t *db,
    const void *s,
    int len,
    int recno)
{
  hash_record_t *hr;
  int bucket = HASH(s, len);
  hr = db->sum_buckets[bucket];
  if (hr == NULL)
    return 0;

  lock_sums_bucket(db, bucket);
  for (hr; hr != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      hr->record_no = recno;
      unlock_sums_bucket(db, bucket);
      return 1;
    }
  }
  unlock_sums_bucket(db, bucket);
  return 0;
}


static int sum_hash_insert(
    db_t *db,
    const void *s,
    int len,
    int *recno)
{
  int bucket = HASH(s, len);
  hash_record_t *hr, *tmp;


  lock_sums_bucket(db, bucket);
  hr = db->sum_buckets[bucket];

  if (hr == NULL) {
    unlock_sums_bucket(db, bucket);
    goto insert;
  }

  /* If you find the hash already, update the record number */
  for (hr; hr != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      *recno = hr->record_no;
      unlock_sums_bucket(db, bucket);
      return 2;
    }
  }
  unlock_sums_bucket(db, bucket);


insert:
  tmp = malloc(sizeof(hash_record_t));
  if (tmp == NULL)
    return 0;
  memset(tmp, 0, sizeof(hash_record_t));
  tmp->keylen = len;
  tmp->key = malloc(len);
  if (!tmp->key) {
    free(tmp);
    return 0;
  }
  memset(tmp->key, 0, len);
  memcpy(tmp->key, s, len);
  tmp->record_no = *recno;
  tmp->next = NULL;

  lock_sums_bucket(db, bucket);
  if (db->sum_buckets[bucket] == NULL)
    db->sum_buckets[bucket] = tmp;
  else {
    tmp->next = db->sum_buckets[bucket];
    db->sum_buckets[bucket] = tmp;
  }
  unlock_sums_bucket(db, bucket);
  return 1;
}


static int sum_hash_delete(
    db_t *db,
    const void *s,
    int len,
    int *recno)
{
  int bucket = HASH(s, len);
  hash_record_t *hr, *tmp;
  hr = db->sum_buckets[bucket];

  /* There is nothing to delete */
  if (hr == NULL)
    return 0;

  lock_sums_bucket(db, bucket);
  tmp = hr;
  if (memcmp(s, hr->key, hr->keylen) == 0) {
    *recno = hr->record_no;
    goto delete;
  }
  for (hr; hr->next != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      *recno = hr->record_no;
      goto delete;
    }
    tmp = hr;
  }
  unlock_sums_bucket(db, bucket);
  return 0;

delete:
  if (hr == tmp) 
    db->sum_buckets[bucket] = hr->next;
  else 
    tmp->next = hr->next;

  unlock_sums_bucket(db, bucket);

  free(hr->key);
  free(hr);
  return 1;
}


static void sum_hash_destroy(
    db_t *db)
{
  hash_record_t *hr, *next;
  for (int i=0; i < MAX_RECORDS * HASH_FACTOR; i++) {
    hr = db->sum_buckets[i];
    if (hr == NULL)
      continue;
    while (hr) {
      next = hr->next;
      free(hr->key);
      free(hr);
      hr = next;
    }
    db->sum_buckets[i] = NULL;
  }
}


static int file_hash_search(
    db_t *db,
    const void *s,
    int len,
    int *recno)
{
  hash_record_t *hr;
  int bucket = HASH(s, len);
  hr = db->file_buckets[bucket];
  if (hr == NULL)
    return 0;

  lock_files_bucket(db, bucket);
  for (hr; hr != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      *recno = hr->record_no;
      unlock_files_bucket(db, bucket);
      return 1;
    }
  }
  unlock_files_bucket(db, bucket);
  return 0;
}

static int file_hash_update_recno(
    db_t *db,
    const void *s,
    int len,
    int recno)
{
  hash_record_t *hr;
  int bucket = HASH(s, len);
  hr = db->file_buckets[bucket];
  if (hr == NULL)
    return 0;

  lock_files_bucket(db, bucket);
  for (hr; hr != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      hr->record_no = recno;
      unlock_files_bucket(db, bucket);
      return 1;
    }
  }
  unlock_files_bucket(db, bucket);
  return 0;
}


static int file_hash_insert(
    db_t *db,
    const void *s,
    int len,
    int *recno)
{
  int bucket = HASH(s, len);
  hash_record_t *hr, *tmp;


  lock_files_bucket(db, bucket);
  hr = db->file_buckets[bucket];

  if (hr == NULL) {
    unlock_files_bucket(db, bucket);
    goto insert;
  }

  /* If you find the hash already, update the record number */
  for (hr; hr != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      *recno = hr->record_no;
      unlock_files_bucket(db, bucket);
      return 2;
    }
  }
  unlock_files_bucket(db, bucket);


insert:
  tmp = malloc(sizeof(hash_record_t));
  if (tmp == NULL)
    return 0;
  memset(tmp, 0, sizeof(hash_record_t));
  tmp->keylen = len;
  tmp->key = malloc(len);
  if (!tmp->key) {
    free(tmp);
    return 0;
  }
  memset(tmp->key, 0, len);
  memcpy(tmp->key, s, len);
  tmp->record_no = *recno;
  tmp->next = NULL;

  lock_files_bucket(db, bucket);
  if (db->file_buckets[bucket] == NULL)
    db->file_buckets[bucket] = tmp;
  else {
    tmp->next = db->file_buckets[bucket];
    db->file_buckets[bucket] = tmp;
  }
  unlock_files_bucket(db, bucket);
  return 1;
}


static int file_hash_delete(
    db_t *db,
    const void *s,
    int len,
    int *recno)
{
  int bucket = HASH(s, len);
  hash_record_t *hr, *tmp;
  hr = db->file_buckets[bucket];

  /* There is nothing to delete */
  if (hr == NULL)
    return 0;

  lock_files_bucket(db, bucket);
  tmp = hr;
  if (memcmp(s, hr->key, hr->keylen) == 0) {
    *recno = hr->record_no;
    goto delete;
  }
  for (hr; hr->next != NULL; hr=hr->next) {
    if (memcmp(s, hr->key, hr->keylen) == 0) {
      *recno = hr->record_no;
      goto delete;
    }
    tmp = hr;
  }
  unlock_files_bucket(db, bucket);
  return 0;

delete:
  if (hr == tmp) 
    db->file_buckets[bucket] = hr->next;
  else 
    tmp->next = hr->next;

  unlock_files_bucket(db, bucket);

  free(hr->key);
  free(hr);
  return 1;
}

static void file_hash_destroy(
    db_t *db)
{
  hash_record_t *hr, *next;
  for (int i=0; i < MAX_RECORDS * HASH_FACTOR; i++) {
    hr = db->file_buckets[i];
    if (hr == NULL)
      continue;
    while (hr) {
      next = hr->next;
      free(hr->key);
      free(hr);
      hr = next;
    }
    db->file_buckets[i] = NULL;
  }
}


int database_build_indexes(
    db_t *db)
{
  db_record_t *rec;
  int recs=0;
  int rc;

  for (int i=0; i < MAX_RECORDS; i++) {
    rec = &db->records[i];
    if (rec->type == TYPE_UNUSED)
      continue;
    rc = i;
    if (!file_hash_insert(db, rec->filename, strlen(rec->filename), &rc))
      return 0;
    if (!sum_hash_insert(db, rec->sha, 32, &rc))
      return 0;

    recs++;
  }
  return recs;
}


db_t * database_open(
    char *filename,
    int flags)
{
  int rc;
  size_t sz = sizeof(db_hdr_t) + (sizeof(db_record_t) * MAX_RECORDS);
  db_t *db = calloc(1, sizeof(db_t));
  if (!db)
    return NULL;
  db->map = NULL;
  db->filename = NULL;

  if ((flags & (DB_CREAT|DB_RDWR)) == (DB_CREAT|DB_RDONLY)) {
    warnx("Cannot open database. Invalid flag parameters");
    goto fail;
  }

  if ((flags & (DB_CREAT|DB_RDWR)) == (DB_CREAT|DB_RDWR)) {
    db->fd = open(filename, O_RDWR|O_CREAT, 0640);
    if (db->fd < 0) {
      warn("Cannot open database");
      goto fail;
    }
    if (fallocate(db->fd, 0, 0, sz) < 0) {
      warn("Cannot allocate data for database file");
      goto fail;
    }
  }
  else if ((flags & DB_RDWR) == DB_RDWR) {
    db->fd = open(filename, O_RDWR);
    if (db->fd < 0) {
      warn("Cannot open database");
      goto fail;
    }
  }
  else if ((flags & DB_RDONLY) == DB_RDONLY) {
    db->fd = open(filename, O_RDONLY);
    if (db->fd < 0) {
      warn("Cannot open database");
      goto fail;
    }
  }

  /* Map into memory */
  if ((flags & DB_RDWR) == DB_RDWR)
    db->map = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, db->fd, 0);
  else
    db->map = mmap(NULL, sz, PROT_READ, MAP_SHARED, db->fd, 0);
  if (db->map == MAP_FAILED) {
    warnx("Cannot open database. Mapping failure");
    goto fail;
  }

  /* Assign the key pointers */
  db->hdr = db->map;
  db->records = (db_record_t *)((uint8_t *)db->map + sizeof(db_hdr_t));

  if ((flags & DB_CREAT) == DB_CREAT)
    db->hdr->magic = DB_MAGIC;
  else {
    if (db->hdr->magic != DB_MAGIC) {
      warnx("Cannot open database: This is not a compatible database file");
      goto fail;
    }
  }

  if (db->hdr->last_pid > 0) {
    if ((rc = kill(db->hdr->last_pid, 0)) == 0) {
      warnx("Cannot open database: The file is in use\n");
      goto fail;
    }
    else if (rc < 0 && errno != ESRCH) {
      warn("Cannot open database due to signal failure");
      goto fail;
    }
  }
  if ((flags & DB_RDWR) == DB_RDWR)
    db->hdr->last_pid = getpid();

  pthread_mutex_init(&db->record_lock, NULL);
  pthread_mutex_init(&db->lock, NULL);
  pthread_cond_init(&db->cond, NULL);

  memset(db->sums_bitmap, 0, BITMAP_SZ*8);
  memset(db->files_bitmap, 0, BITMAP_SZ*8);

  db->sz = sz;
  db->filename = strdup(filename);

  database_build_indexes(db);

  return db;
   
fail:
  if (db) {
    if (db->filename)
      free(db->filename);
    if (db->map)
      munmap(db->map, sz);
    close(db->fd);
    free(db);
  }
  return NULL;

}

void database_close(
    db_t *db) 
{
  if (db) {
    if (db->filename)
      free(db->filename);
    if (db->map) {
      msync(db->map, db->sz, MS_SYNC);
      munmap(db->map, db->sz);
    }
    close(db->fd);
    file_hash_destroy(db);
    sum_hash_destroy(db);
    free(db);
  }
}

int database_insert(
    db_t *db,
    char *filename,
    char sha[32],
    off_t offset,
    size_t len,
    char type)
{
  uint32_t recno;
  uint32_t o_recno;
  int rc, rc2;
  db_record_t *rec;

  pthread_mutex_lock(&db->record_lock);
  o_recno = db->hdr->next_record_no;

  rc = file_hash_insert(db, filename, strlen(filename), &recno);
  recno = o_recno;
  if (rc == 0) {
    pthread_mutex_unlock(&db->record_lock);
    return 0;
  }
  else if (rc == 2) {
    rec = &db->records[recno];
    if (rec->type == TYPE_STATIC && type != TYPE_STATIC) {
      pthread_mutex_unlock(&db->record_lock);
      return -1; /* Tried to overwrite a static filename */
    }
    else if (rec->type == TYPE_UNUSED) {
      pthread_mutex_unlock(&db->record_lock);
      return -2; /* Internal error. Found a conflicting filename 
                    to an unused record */
    }
  }
  else {
    /* Dynamics can be overwritten */
    rec = &db->records[recno];
  }

  /* Do not overwrite static entries unless its a static entry declared */ 
  while (rec->type == TYPE_STATIC && type != TYPE_STATIC) {
    recno++;
    rec = &db->records[recno];  
    if (recno >= MAX_RECORDS)
      recno = 0;
  }

  /* If the hash insert was new -- this can fail */
  if (rc == 1) {
    if (rec->type == TYPE_DYNAMIC || (rec->type == TYPE_STATIC && type == TYPE_STATIC)) {
      file_hash_delete(db, rec->filename, strlen(filename), &rc2);
      sum_hash_delete(db, rec->sha, 32, &rc2);
    }
  }

  rc2 = sum_hash_insert(db, sha, 32, &recno);
  if (rc2 == 0 || rc2 == 2) {
    pthread_mutex_unlock(&db->record_lock);
    return -3; /* The sha sum already exists */
  }

  strncpy(rec->filename, filename, 48);
  memcpy(rec->sha, sha, 32);
  rec->type = type;
  rec->len = len;
  rec->offset = offset; 
  if (rc == 1) 
    db->hdr->next_record_no++;
  if (db->hdr->next_record_no >= MAX_RECORDS)
    db->hdr->next_record_no = 0;

  /* This is a bit clumsy but its probably OK */
  file_hash_update_recno(db, filename, strlen(filename), recno);
  sum_hash_update_recno(db, sha, 32, recno);

  pthread_mutex_unlock(&db->record_lock);
  return 1;
}

void database_record_free(
    db_record_t *rec)
{
  if (rec)
    free(rec);
}

db_record_t * database_get_file(
    db_t *db,
    char *filename)
{
  db_record_t *rec, *new;
  int rc;
  int recno;
  rc = file_hash_search(db, filename, strlen(filename), &recno);
  if (rc) {
    rec = &db->records[recno];
    new = malloc(sizeof(db_record_t));
    memcpy(new, rec, sizeof(db_record_t));
    return new;
  }
  else
    return NULL;
}

db_record_t * database_get_sum(
    db_t *db,
    char *sum)
{
  db_record_t *rec, *new;
  int rc;
  int recno;
  rc = sum_hash_search(db, sum, 32, &recno);
  if (rc) {
    rec = &db->records[recno];
    new = malloc(sizeof(db_record_t));
    memcpy(new, rec, sizeof(db_record_t));
    return new;
  }
  else
    return NULL;
}


db_record_t * database_get_random(
    db_t *db,
    int *seed)
{
  int recno;
  db_record_t *rec, *new;
  recno = rand_r(seed);
  pthread_mutex_lock(&db->record_lock);
  recno = recno % db->hdr->next_record_no;
  for (int i=0; i < MAX_RECORDS; i++) {
    rec = &db->records[recno];
    if (rec->type == TYPE_UNUSED) {
      recno++;
      if (recno == MAX_RECORDS)
        recno = 0;
      continue;
    }
    pthread_mutex_unlock(&db->record_lock);
    new = malloc(sizeof(db_record_t));
    memcpy(new, rec, sizeof(db_record_t));
    return new;
  }
  pthread_mutex_unlock(&db->record_lock);
  return NULL;
}

int database_import_static_checksums(
     db_t *db,
     char *filename)
{
  int rc, inserts=0;
  char sum[65];
  char sha[32];
  char name[49];
  char q;
  FILE *checksum_file = NULL;

  checksum_file = fopen(filename, "r");
  if (!checksum_file)
    return -1;

  while (!feof(checksum_file)) {
    inserts++;
    memset(sha, 0, 32);
    rc = fscanf(checksum_file, "%64s  %48s\n", sum, name);

    for (int i=0; i < 32; i++)
      sscanf(sum+(i*2), "%02hhx", &sha[i]);
    if (!database_insert(db, name, sha, 0, 0, TYPE_STATIC))
      warnx("Cannot insert into db!\n");
  }

  return inserts;
}
