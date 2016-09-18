#include "common.h"
#include "ndmp_common.h"

bool ndmp_send_log_message_post(
		ndmp_session *sess,
		ndmp_log_type type,
		char *message)
{
   ndmp_log_message_post log;
   memset(&log, 0, sizeof(log));

   if(!ndmp_header_send(sess, NDMP_LOG_MESSAGE))
      goto fail;

   sess->xdrs.x_op = XDR_ENCODE;
   log.log_type = type;
	log.message_id = time(NULL);
	log.entry = strdup(message);
	log.associated_message_valid = NDMP_NO_ASSOCIATED_MESSAGE;
	log.associated_message_sequence = 0;

   if (!xdr_ndmp_log_message_post(&sess->xdrs, &log)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_log_message_post, &log);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_log_message_post, &log);
   return false;	
}
