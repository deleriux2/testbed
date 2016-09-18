#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mntent.h>

#include <sched.h>

#define SNAPSHOT_SUBVOLUME "backups"
#define SNAPSHOT_MOUNTPOINT "/mnt/backup"

void validate_path(
    char *in,
    char **out)
{
  char *path;
  struct stat st;
  if ((path = realpath(in, NULL)) == NULL)
    err(EXIT_FAILURE, "Cannot resolve path %s", in);

  /* According to btrfs-progs, a valid subvolume is always inode 256 */
  if (stat(path, &st) < 0)
    err(EXIT_FAILURE, "Cannot stat resolved path %s", path);

  if (st.st_ino != 256 || !S_ISDIR(st.st_mode))
    errx(EXIT_FAILURE, "The path %s (%s) is not a subvolume", in, path);

  *out = path;
  return;  
}

void initialize(
    void)
{
  /* Unshare the mount namespace */
  if (unshare(CLONE_NEWNS) < 0)
    err(EXIT_FAILURE, "Cannot invoke unshare system call");

  /* Prepare to mount SNAPSHOT_MOUNTPIONT */
  if (mkdir(SNAPSHOT_MOUNTPOINT, 0700) < 0) {
    if (errno != EEXIST)
      err(EXIT_FAILURE, "Cannot create snapshot mounpiont directory %s", SNAPSHOT_MOUNTPOINT);
  }

  /* Mount the filesystem */
  
}

int main(
    const char argc,
    char **argv)
{
  char *path = NULL;

  if (argc < 2)
    errx(EXIT_FAILURE, "Must pass in the btrfs path to a valid subvolume root");

  validate_path(argv[1], &path);

  initialize();
  exit(0);
}
