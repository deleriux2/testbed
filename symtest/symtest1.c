#include <stdlib.h>
#include <stdio.h>

extern int superglobal;
int global = 123;

void run_test(void)
{
	printf("This is the first plugin: %d, %d\n", global, superglobal);
	return;
}
