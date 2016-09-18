#include "common.h"
#include "ndmp_common.h"

#include <netdb.h>

bool ndmp_send_data_connect_request(
      ndmp_session *sess,
      const char *host,
      const char *port)
{
   struct addrinfo *ai = NULL;
   ndmp_tcp_addr *tcp = NULL;
   ndmp_data_connect_request dconnect;
   memset(&dconnect, 0, sizeof(dconnect));

   ON_FALSE(fail, (tcp = malloc(sizeof(*tcp))) != NULL);
   ON_FALSE(fail, !getaddrinfo(host, port, NULL, &ai));
   dconnect.addr.ndmp_addr_u.tcp_addr.tcp_addr_len = 1;
   dconnect.addr.ndmp_addr_u.tcp_addr.tcp_addr_val = tcp;
   tcp->ip_addr = htonl(((struct sockaddr_in *)(ai->ai_addr))->sin_addr.s_addr);
   tcp->port = htons(((struct sockaddr_in *)(ai->ai_addr))->sin_port);
   tcp->addr_env.addr_env_len = 0;
   tcp->addr_env.addr_env_val = NULL;
   dconnect.addr.addr_type = NDMP_ADDR_TCP;

   ON_FALSE(fail, ndmp_header_send(sess, NDMP_DATA_CONNECT));

   sess->xdrs.x_op = XDR_ENCODE;
   ON_FALSE(fail, xdr_ndmp_data_connect_request(&sess->xdrs, &dconnect));
   ON_FALSE(fail, xdrrec_endofrecord(&sess->xdrs, 1));

   xdr_free((xdrproc_t)xdr_ndmp_data_connect_request, &dconnect);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_request, &dconnect);
   return false;

}

bool ndmp_recv_data_connect_reply(
      ndmp_session *sess)
{
   ndmp_data_connect_reply reply;
   memset(&reply, 0, sizeof(reply));

   REPLY_HEADER_CHECKS(NDMP_DATA_CONNECT);

   sess->xdrs.x_op = XDR_DECODE;
   ON_FALSE(fail, xdr_ndmp_data_connect_reply(&sess->xdrs, &reply));
   ON_FALSE(fail, reply.error == NDMP_NO_ERR);

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, &reply);
   return false;
}

