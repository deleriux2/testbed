#include "common.h"
#include "ndmp_common.h"
#include "ndmp.h"

#include <arpa/inet.h>
#include <sys/socket.h>

bool ndmp_send_data_connect_request(
		ndmp_session *sess)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = 1;
	socklen_t addrlen = sizeof(addr);
	int i;
	int fd;
	bool bound = false;

	ndmp_data_connect_request *dconnect;
	if ((dconnect = malloc(sizeof(*dconnect))) == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return false;
	}
	ndmp_tcp_addr tcp;

   if (!ndmp_header_send(sess, NDMP_DATA_CONNECT)) {
      goto fail;
   }

	if (getsockname(sess->fd, (struct sockaddr *)&addr, &addrlen) < 0) {
		fprintf(stderr, "Cannot obtain socket address");
		goto fail;
	}

	/* Setup a databackup socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Could not create socket: %s\n", strerror(errno));
		goto fail;
	}
	i = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &i, 4) < 0) {
		fprintf(stderr, "Cannot setsockopt on data socket: %s\n", strerror(errno));
		goto fail;
	}

	for (i=NDMPBACKUP_PORT_START; i < NDMPBACKUP_PORT_END; i++) {
		addr.sin_port = htons(i);
		if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
			continue;
		}
		bound = true;
		break;
	}

	if (!bound) {
		fprintf(stderr, "Unable to find an address to bind to\n");
		goto fail;
	}

	if (listen(fd, 1) < 0) {
		fprintf(stderr, "Cannot set listen on socket: %s\n", strerror(errno));
		goto fail;
	}

	/* Create the request */
	tcp.ip_addr = addr.sin_addr.s_addr;
	tcp.port = addr.sin_port;
	tcp.addr_env.addr_env_len = 0;
	tcp.addr_env.addr_env_val = NULL;
	dconnect->addr.addr_type = NDMP_ADDR_TCP;
	dconnect->addr.ndmp_addr_u.tcp_addr.tcp_addr_len = 1;
	dconnect->addr.ndmp_addr_u.tcp_addr.tcp_addr_val = &tcp;

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_data_connect_request(&sess->xdrs, dconnect)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

	free(dconnect);
   return true;

fail:
	close(fd);
	free(dconnect);
	return false;
}


bool ndmp_recv_data_connect_reply(
      ndmp_session *sess)
{
   ndmp_header hdr;
   ndmp_data_connect_reply *dreply;
   ON_ERR("Memory allocation error", dreply = malloc(sizeof(*dreply)));
   bool success = false;
   int rc;
   int i;

   if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
      fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
      return false;
   }

   if (hdr.message_type != NDMP_MESSAGE_REPLY) {
      fprintf(stderr, "Expected a message request but got something else\n");
   }
   if (hdr.message_code != NDMP_DATA_CONNECT) {
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_connect_reply(&sess->xdrs, dreply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

   if (dreply->error != NDMP_NO_ERR) {
      fprintf(stderr, "Error getting server to connect to our backup host: %s\n", ndmp_print_error(dreply->error));
      goto fail;
   }

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, dreply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, dreply);
   return false;
}
