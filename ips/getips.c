#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
  struct ifaddrs *addrs;
  struct ifaddrs *n;

  getifaddrs(&addrs);
  struct sockaddr_in *a;

  for (n=addrs; n != NULL; n=n->ifa_next) {
    a = (struct sockaddr_in *)n->ifa_addr;
    if (a->sin_family == AF_INET) {
      printf("%s %p\n", inet_ntoa(a->sin_addr), n->ifa_data);
    }
  }

  freeifaddrs(addrs); 
}
