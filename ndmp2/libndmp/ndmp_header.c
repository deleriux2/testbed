#include "common.h"
#include "ndmp_common.h"
#include "ndmp.h"

int ndmp_header_recv(
      ndmp_session *sess,
      ndmp_header *hdr)
{
   assert(sess);
   assert(hdr);

   /* Get the header */
   ++sess->peer_seqno;
   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_header(&sess->xdrs, hdr))
      SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_RECV_DECODE, fail);
   if (hdr->error_code != NDMP_NO_ERR) {
      SET_ERR(sess, MAJ_HEADER_ERROR, hdr->error_code, fail);
   }
   return 1;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   return -1;
}

int ndmp_header_send(
      ndmp_session *sess,
      ndmp_message code)
{
   assert(sess);

   /* Generate a valid header */
   ndmp_header hdr;
   hdr.sequence = ++sess->seqno;
   hdr.time_stamp = time(NULL);
   hdr.message_type = NDMP_MESSAGE_REQUEST;
   hdr.message_code = code;
   hdr.reply_sequence = 0;
   hdr.error_code = 0;

   sess->xdrs.x_op = XDR_ENCODE;
   /* To send this, we need to put the header into the xdr stream */
   if (!xdr_ndmp_header(&sess->xdrs, &hdr))
     SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_SEND_ENCODE, fail);
   return 1;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   return 0;
}
