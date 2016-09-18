#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
void print_cmdline(void);
 
int main(int argc, char **argv) {
char *end;
print_cmdline();
end = argv[argc-1] + strlen(argv[argc-1]);
memset(*argv, 0, end-*argv);
print_cmdline();
return 0;
}
 
void print_cmdline() {
FILE* fd = fopen("/proc/self/cmdline", "r");
char buf[1024];
size_t len = fread(buf, 1, 1023, fd);
buf[len] = '\n';
fwrite(buf, len+1, 1, stdout);
fflush(stdout);
}
