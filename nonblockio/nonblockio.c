#include <stdio.h>
#include <stdint.h>
#include <libaio.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>

int main()
{
	int fd;
	int rc;
	int i;
	io_context_t ctx;
	struct iocb cb;
	struct iocb *pcb = &cb;	
	struct io_event ev[1];
	char buf[4096];

	if ((fd = open("/etc/passwd", O_RDONLY, 0)) < 0)
		err(EX_SOFTWARE, "FD OPEN FAILED");

	memset(buf, 0, sizeof(buf));
	memset(&ctx, 0, sizeof(ctx));
	memset(&cb, 0, sizeof(cb));

	if ((rc = io_setup(64, &ctx)) != 0) {
		errno = -rc;
		err(EX_SOFTWARE, "IO_SETUP FAILED");
	}

	io_prep_pread(&cb, fd, buf, 4096, 0);

	if ((rc = io_submit(ctx, 1, &pcb)) != 1) {
		errno = -rc;
		err(EX_SOFTWARE, "IO_SUBMIT FAILED");
	}

	if ((rc = io_getevents(ctx, 1, 1, ev, NULL)) != 1) {
		errno = -rc;
		err(EX_SOFTWARE, "IO_GETEVENTS FAILED");
	}	

	printf("%d\n", ev[0].res);
	for (i=0; i < rc; i++) {
		if (ev[0].res < 0) {
			errno = -ev[0].res;
			err(EX_SOFTWARE, "READ FAILED");
		}
		printf("Data:\n%s", ev[0].obj->u.c.buf);
	}

	return 0;
}
