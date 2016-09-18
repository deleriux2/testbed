#include "common.h"
#include "ndmp_common.h"

#include <netdb.h>
#include <sys/socket.h>
#include <signal.h>

static int setup_dma_server(
		int fd)
{
	ndmp_session *sess = NULL;
	pid_t pid = fork();
	if (pid > 0) {
		return 0;
	}
	signal(SIGCHLD, SIG_DFL);

	sess = ndmp_init_session(fd);
	if (!sess) {
		fprintf(stderr, "Cannot setup ndmp session\n");
		goto fail;
	}

	/* Send the notification */
	if (!ndmp_send_notify_connection_status(sess, NDMP_CONNECTED, "")) 
		goto fail;

	if (!ndmp_data_server_dispatcher(sess))
		goto fail;

fail:
	ndmp_free_session(sess);
	exit(0);
}

static int tcp_server(
		char *port)
{
	int fd = -1;
	int yes = 1;
	int rc;
	struct addrinfo hints, *ai = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;

	if ((rc = getaddrinfo(NULL, port, &hints, &ai)) != 0) {
		fprintf(stderr, "Cannot getaddrinfo: %s\n", gai_strerror(rc));
		exit(1);
	}

	ON_ERR("Cannot create socket", fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, ai->ai_protocol));
	ON_ERR("Cannot setsockopt", setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)));

	ON_ERR("Cannot bind to address", bind(fd, ai->ai_addr, ai->ai_addrlen));
	ON_ERR("Cannot setup listen", listen(fd, 5));

	freeaddrinfo(ai);
	return fd;
}

int main()
{
	signal(SIGCHLD, SIG_IGN);
	int clifd = -1;
	int fd = tcp_server("10000");

	while (1) {
		clifd = accept4(fd, NULL, 0, SOCK_CLOEXEC);
		if (clifd < 0 && errno == EINTR) {
			continue;
		}
		else if (clifd < 0) {
			perror("Clifd");
			continue;
		}
		setup_dma_server(clifd);
		close(clifd);
	}
	return 0;
}
