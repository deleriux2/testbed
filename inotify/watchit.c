#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <errno.h>

#define WATCHDIR "./watched"

void child_run(void)
{
	printf("Child spawned..\n");
	int fd;
	if (chdir(WATCHDIR))
		err(EX_OSERR, "Cannot chdir in child");

	/* Care not if this fails.. */
	unlink("myfile.dat");

	while (1) {
		fd = open("myfile.dat", O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			warn("Cannot create necessary file.. sleeping");
			sleep(1);
		}
		close(fd);
		fd = -1;
		if (unlink("myfile.dat") < 0)
			err(EX_OSERR, "Cannot unlink file in watched directory");
	}
	
}

int main() 
{
	int watch_fd = -1;
	int watched = -1;
	struct inotify_event ev[128];
	memset(ev, 0, sizeof(&ev)*128);

	if (mkdir(WATCHDIR, S_IRWXU) < 0) {
		if (errno != EEXIST) {
			err(EX_OSERR, "Cannot create directory");
		}
	}

	if (fork() == 0) {
		child_run();
		exit(0);
	}

	while (1) {
		if ((watch_fd = inotify_init1(IN_CLOEXEC)) < 0)
			err(EX_OSERR, "Cannot init inotify");

		if (watch_fd < 0)
			err(EX_OSERR, "Cannot init watch");

		if ((watched = inotify_add_watch(watch_fd, WATCHDIR, IN_CREATE)) < 0)
			err(EX_OSERR, "Cannot add watched directory");

		if (read(watch_fd, ev, sizeof(ev)*128) < 0)
			err(EX_OSERR, "Cannot read from watcher");

		if (inotify_rm_watch(watch_fd, watched) < 0)
			err(EX_OSERR, "Cannot remove watch");

		close(watch_fd);
	}
	return 0;
}
