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
	if (!xdr_ndmp_header(&sess->xdrs, hdr)) {
		xdrrec_skiprecord(&sess->xdrs);
		return -1;
	}
	if (hdr->error_code != NDMP_NO_ERR) {
		return 0;
	}

	return 1;
}

int ndmp_header_send_error_reply(
		ndmp_session *sess,
		ndmp_message code,
		ndmp_error error)
{
	ndmp_header hdr;
	hdr.sequence = ++sess->seqno;
	hdr.time_stamp = time(NULL);
	hdr.message_type = NDMP_MESSAGE_REPLY;
	hdr.message_code = code;
	hdr.reply_sequence = sess->seqno;
	hdr.error_code = error;

	sess->xdrs.x_op = XDR_ENCODE;
	/* To send this, we need to put the header into the xdr stream */
	if (!xdr_ndmp_header(&sess->xdrs, &hdr)) {
		xdrrec_skiprecord(&sess->xdrs);
		return 0;
	}

	return 1;
}

int ndmp_header_send_reply(
		ndmp_session *sess,
		ndmp_message code)
{
	ndmp_header hdr;
	hdr.sequence = ++sess->seqno;
	hdr.time_stamp = time(NULL);
	hdr.message_type = NDMP_MESSAGE_REPLY;
	hdr.message_code = code;
	hdr.reply_sequence = sess->peer_seqno;
	hdr.error_code = 0;

	sess->xdrs.x_op = XDR_ENCODE;
	/* To send this, we need to put the header into the xdr stream */
	if (!xdr_ndmp_header(&sess->xdrs, &hdr)) {
		xdrrec_skiprecord(&sess->xdrs);
		return 0;
	}

	return 1;
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
	if (!xdr_ndmp_header(&sess->xdrs, &hdr)) {
		xdrrec_skiprecord(&sess->xdrs);
		return 0;
	}

	return 1;
}

char * ndmp_print_error(
		ndmp_error error_code)
{
	switch (error_code) {
	case NDMP_NO_ERR:
	return "No error";
	case NDMP_NOT_SUPPORTED_ERR:
	return "Request not supported";
	case NDMP_DEVICE_BUSY_ERR:
	return "Device is busy";
	case NDMP_DEVICE_OPENED_ERR:
	return "Device is already opened";
	case NDMP_NOT_AUTHORIZED_ERR:
	return "Not authorized";
	case NDMP_PERMISSION_ERR:
	return "Permission denied";
	case NDMP_DEV_NOT_OPEN_ERR:
	return "Device is not open";
	case NDMP_IO_ERR:
	return "IO Error";
	case NDMP_TIMEOUT_ERR:
	return "Timed out";
	case NDMP_ILLEGAL_ARGS_ERR:
	return "Arguments requested were illegal";
	case NDMP_NO_TAPE_LOADED_ERR:
	return "Tape is not loaded";
	case NDMP_WRITE_PROTECT_ERR:
	return "Write protection error";
	case NDMP_EOF_ERR:
	return "End of file";
	case NDMP_EOM_ERR:
	return "End of message";
	case NDMP_FILE_NOT_FOUND_ERR:
	return "File not found";
	case NDMP_BAD_FILE_ERR:
	return "Bad file";
	case NDMP_NO_DEVICE_ERR:
	return "No such device";
	case NDMP_NO_BUS_ERR:
	return "No bus";
	case NDMP_XDR_DECODE_ERR:
	return "XDR decode error";
	case NDMP_ILLEGAL_STATE_ERR:
	return "Illegal state";
	case NDMP_UNDEFINED_ERR:
	return "Undefined error";
	case NDMP_XDR_ENCODE_ERR:
	return "XDR Encode error";
	case NDMP_NO_MEM_ERR:
	return "No memory";
	case NDMP_CONNECT_ERR:
	return "Connect error";
	case NDMP_SEQUENCE_NUM_ERR:
	return "Invalid sequence/Out of sequence";
	case NDMP_READ_IN_PROGRESS_ERR:
	return "Read in progress";
	case NDMP_PRECONDITION_ERR:
	return "Precondition";
	case NDMP_CLASS_NOT_SUPPORTED_ERR:
	return "Unsupported class";
	case NDMP_VERSION_NOT_SUPPORTED_ERR:
	return "Version is not supported";
	case NDMP_EXT_DUPL_CLASSES_ERR:
	return "Duplicate class error";
	case NDMP_EXT_DANDN_ILLEGAL_ERR:
	return "Extension dandn illegal";
	default:
	return "System error";
	}
}

bool ndmp_header_authorisation_required(
		ndmp_message message_code)
{
	switch(message_code) {
		case NDMP_CONFIG_GET_HOST_INFO:
		case NDMP_CONFIG_GET_CONNECTION_TYPE:
		case NDMP_CONFIG_GET_BUTYPE_INFO:
		case NDMP_CONFIG_GET_FS_INFO:
		case NDMP_CONFIG_GET_TAPE_INFO:
		case NDMP_CONFIG_GET_SCSI_INFO:
		case NDMP_CONFIG_SET_EXT_LIST:
		case NDMP_CONFIG_GET_EXT_LIST:
		case NDMP_SCSI_OPEN:
		case NDMP_SCSI_CLOSE:
		case NDMP_SCSI_GET_STATE:
		case NDMP_SCSI_RESET_DEVICE:
		case NDMP_SCSI_EXECUTE_CDB:
		case NDMP_TAPE_OPEN:
		case NDMP_TAPE_CLOSE:
		case NDMP_TAPE_GET_STATE:
		case NDMP_TAPE_MTIO:
		case NDMP_TAPE_WRITE:
		case NDMP_TAPE_READ:
		case NDMP_TAPE_EXECUTE_CDB:
		case NDMP_DATA_GET_STATE:
		case NDMP_DATA_START_BACKUP:
		case NDMP_DATA_START_RECOVER:
		case NDMP_DATA_ABORT:
		case NDMP_DATA_GET_ENV:
		case NDMP_DATA_STOP:
		case NDMP_DATA_LISTEN:
		case NDMP_DATA_CONNECT:
		case NDMP_DATA_START_RECOVER_FILEHIST:
		case NDMP_NOTIFY_DATA_HALTED:
		case NDMP_NOTIFY_CONNECTION_STATUS:
		case NDMP_NOTIFY_MOVER_HALTED:
		case NDMP_NOTIFY_MOVER_PAUSED:
		case NDMP_NOTIFY_DATA_READ:
		case NDMP_LOG_FILE:
		case NDMP_LOG_MESSAGE:
		case NDMP_FH_ADD_FILE:
		case NDMP_FH_ADD_DIR:
		case NDMP_FH_ADD_NODE:
		case NDMP_MOVER_GET_STATE:
		case NDMP_MOVER_LISTEN:
		case NDMP_MOVER_CONTINUE:
		case NDMP_MOVER_ABORT:
		case NDMP_MOVER_STOP:
		case NDMP_MOVER_SET_WINDOW:
		case NDMP_MOVER_READ:
		case NDMP_MOVER_CLOSE:
		case NDMP_MOVER_SET_RECORD_SIZE:
		case NDMP_MOVER_CONNECT:
		case NDMP_EXT_STANDARD_BASE:
		case NDMP_EXT_PROPRIETARY_BASE:
		return true;
		break;
		default:
		return false;
		break;
	}
}
