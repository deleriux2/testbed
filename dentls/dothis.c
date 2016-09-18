#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
 
/* filter for regular files only */
static int dirent_select(const struct dirent* ent)
{
return ent->d_type == DT_REG;
}
 
/* goes to the directory in argv[1] and removes all regular files within */
int main(int argc, char* argv[])
{
if (argc != 2) {
fprintf(stderr, "directory to delete from is required\n");
return 1;
}
 
int res = chdir(argv[1]);
if (res) {
perror("chdir");
return 1;
}
 
/* make the list of files to delete */
struct dirent** list;
int count = scandir(".", &list, dirent_select, NULL);
if (count < 0) {
perror("scandir");
return 1;
}
 
/* fork twice to become four processes total */
pid_t pid1 = fork();
pid_t pid2 = fork();
if (pid1 < 0 || pid2 < 0) {
perror("fork");
return 1;
}
 
/* figure out who is responsible for which files (one case per process) */
int begin, end;
if (pid1 == 0 && pid2 == 0) {
begin = 0;
end = count / 4;
} else if (pid2 == 0) {
begin = count / 4;
end = count / 2;
} else if (pid1 == 0) {
begin = count / 2;
end = count * 3 / 4;
} else {
begin = count * 3 / 4;
end = count;
}
 
/* now delete the files this process is responsible for */
int ii;
for (ii = begin; ii < end; ++ii) {
res = unlink(list[ii]->d_name);
if (res) {
perror("unlink");
return 1;
}
}
 
return 0;
}
