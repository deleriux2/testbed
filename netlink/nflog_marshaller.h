/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _NFLOG_MARSHALLER_H_RPCGEN
#define _NFLOG_MARSHALLER_H_RPCGEN

#include <rpc/rpc.h>


#ifdef __cplusplus
extern "C" {
#endif

#define NFLOG_PROTO_ICMP 1
#define NFLOG_PROTO_TCP 6
#define NFLOG_PROTO_UDP 17

struct portspec {
	u_int srcport;
	u_int dstport;
};
typedef struct portspec portspec;

struct icmpspec {
	u_int code;
	u_int type;
};
typedef struct icmpspec icmpspec;

struct nflog_log_timestamp {
	int tv_sec;
	int tv_usec;
};
typedef struct nflog_log_timestamp nflog_log_timestamp;

struct protocol_data {
	u_int protocol;
	union {
		icmpspec icmp;
		portspec tcp;
		portspec udp;
	} protocol_data_u;
};
typedef struct protocol_data protocol_data;

struct nflog_log {
	char *user;
	char *group;
	char *indev;
	char *outdev;
	char *physindev;
	char *physoutdev;
	char *prefix;
	char *hwaddr;
	char *payload;
	nflog_log_timestamp ts;
	int payloadlen;
	int mark;
	u_int pktsz;
	u_int ttl;
	char *protocol;
	char *srcaddr;
	char *dstaddr;
	protocol_data pdata;
};
typedef struct nflog_log nflog_log;

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_portspec (XDR *, portspec*);
extern  bool_t xdr_icmpspec (XDR *, icmpspec*);
extern  bool_t xdr_nflog_log_timestamp (XDR *, nflog_log_timestamp*);
extern  bool_t xdr_protocol_data (XDR *, protocol_data*);
extern  bool_t xdr_nflog_log (XDR *, nflog_log*);

#else /* K&R C */
extern bool_t xdr_portspec ();
extern bool_t xdr_icmpspec ();
extern bool_t xdr_nflog_log_timestamp ();
extern bool_t xdr_protocol_data ();
extern bool_t xdr_nflog_log ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_NFLOG_MARSHALLER_H_RPCGEN */