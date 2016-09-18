#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <err.h>
#include <sysexits.h>

void (*do_test1)(void);
void (*do_test2)(void);

//extern int superglobal;
int superglobal = 5555;

int main() {
	void *plug1 = NULL;
	void *plug2 = NULL;
	if ((plug1 = dlopen("./symtest1.so", RTLD_LAZY|RTLD_GLOBAL)) == NULL)
		errx(EX_SOFTWARE, "dlopen failed: %s", dlerror());
	if ((plug2 = dlopen("./symtest2.so", RTLD_LAZY|RTLD_GLOBAL)) == NULL)
		errx(EX_SOFTWARE, "dlopen failed: %s", dlerror());

	dlerror();
	do_test1 = dlsym(plug1, "run_test");
	if (do_test1 == NULL)
		errx(EX_SOFTWARE, "dlsym failed: %s", dlerror());

	dlerror();
	do_test2 = dlsym(plug2, "run_test");
	if (do_test2 == NULL)
		errx(EX_SOFTWARE, "dlsym failed: %s", dlerror());

	do_test1();
	do_test2();	
	return 0;
}
