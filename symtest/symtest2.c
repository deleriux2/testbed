#include <stdlib.h>
#include <stdio.h>

extern int superglobal;
int global = 234;

void run_test(void)
{
	printf("This is the second plugin: %d, %d\n", global, superglobal);
	return;
}
