#ifndef NDMP_ERROR_H
#define NDMP_ERROR_H

#define MAJ_NO_ERROR 0
#define MAJ_SYSTEM_ERROR 1
#define MAJ_LOOKUP_ERROR 2
#define MAJ_APPLICATION_ERROR 3
#define MAJ_HEADER_ERROR 4
#define MAJ_CONNECT_ERROR 5
#define MAJ_XDR_ERROR 6
#define MAJ_CONFIG_ERROR 7

/* The header error types
 * There are a lot more message codes specified in the protocol
 * These are the additional ones needed for the library to detect failures
 * during processing */
#define MIN_HEADER_RECV_DECODE 30
#define MIN_HEADER_NOT_REQUEST 31
#define MIN_HEADER_SEND_ENCODE 32
#define MIN_HEADER_BAD_MESSAGECODE 33
#define MIN_HEADER_NOT_REPLY 34
#define MIN_HEADER_BAD_SEQNO 35

/* The connection status error types. There are a few types specified in the
 * specification too */
#define STATUS_POST_DECODE 3
#define INVALID_PROTOCOL_VERSION 4
#define OPEN_ENCODE 5
#define OPEN_DECODE 6
#define HASH_FAIL 7
#define AUTH_ENCODE 8
#define AUTH_DECODE 9

/* XDR transport error routines */
#define SEND_ERROR 0
#define RECV_ERROR 1

/* Ndmp config errors */
#define UNSUPPORTED_AUTH 0
#define GET_AUTH_ENCODE 1
#define GET_AUTH_DECODE 2
#define SERVER_INFO_ENCODE 3
#define SERVER_INFO_DECODE 4
#define AUTH_MECH_CONTRADICTION 5
#define FSINFO_ENCODE 6
#define FSINFO_DECODE 7
#define BUINFO_ENCODE 8
#define BUINFO_DECODE 9


#endif
