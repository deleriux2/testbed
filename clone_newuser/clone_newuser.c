#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

int runshell(void *data) {
	printf("Executing shell..\n");
	execlp("/bin/bash", "bash", NULL);
	perror("exec error");
	exit(1);
}

int main() {
	int status;
	void *stack = malloc(1<<20);
	memset(stack, 0, 1<<20);

	if (clone(runshell, stack+(1<<20), CLONE_NEWUSER|SIGCHLD, NULL) < 0) {
		perror("clone");
		exit(1);
	}
	if (wait(&status) < 0) {
		perror("wait");
		exit(1);
	}
	printf("Waited to finish..\n");
	exit(0);
}
