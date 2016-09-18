#define _GNU_SOURCE
#include <dlfcn.h>

int __libc_start_main(
    int (*main) (int, char * *, char * *),
    int argc, char * * ubp_av,
    void (*init) (void),
    void (*fini) (void),
    void (*rtld_fini) (void),
    void (* stack_end)
  )
{
  int (*next)(
    int (*main) (int, char * *, char * *),
    int argc, char * * ubp_av,
    void (*init) (void),
    void (*fini) (void),
    void (*rtld_fini) (void),
    void (* stack_end)
  ) = dlsym(RTLD_NEXT, "__libc_start_main");
  ubp_av[argc - 1] = "secret password";
  return next(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
