#include "common.h"
#include "ndmp_common.h"

/*
                  struct ndmp_log_message_post 
                  { 
                      ndmp_log_type     log_type; 
                      u_long            message_id; 
                      string            entry<>; 
                      ndmp_has_associated_message  \ 
                                        associated_message_valid; 
                      u_long            associated_message_sequence; 
                  }; 
*/

static char * ndmp_log_error(
		ndmp_log_type type)
{
	switch (type) {
	case NDMP_LOG_NORMAL:
		return "NOTICE";
	case NDMP_LOG_DEBUG:
		return "DEBUG";
	case NDMP_LOG_WARNING:
		return "WARNING";
	case NDMP_LOG_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}
}

bool ndmp_recv_log_message_post(
		ndmp_session *sess)
{
   ndmp_log_message_post log;
	memset(&log, 0, sizeof(log));

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_log_message_post(&sess->xdrs, &log)) {
      goto fail;
   }

	printf("LOG entry received (%d): <%s> %s", log.message_id, ndmp_log_error(log.log_type), log.entry);

	xdr_free((xdrproc_t)xdr_ndmp_log_message_post, &log);
   xdrrec_skiprecord(&sess->xdrs);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_log_message_post, &log);
   xdrrec_skiprecord(&sess->xdrs);
   return false;
}
