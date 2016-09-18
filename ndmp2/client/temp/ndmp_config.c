#include "common.h"
#include "ndmp.h"
#include "ndmp_common.h"

bool ndmp_send_config_get_server_info_request(
		ndmp_session *sess)
{
	if (!ndmp_header_send(sess, NDMP_CONFIG_GET_SERVER_INFO)) {
		return false;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		return 0;
	}	
	return true;
}


/* Discover if server supports md5 authentication and fill in any other data
 * necessary */
bool ndmp_recv_config_get_server_info_reply(
		ndmp_session *sess)
{
	ndmp_header hdr;
	ndmp_config_get_server_info_reply *info;
	ON_ERR("memory allocation error", info = calloc(sizeof(*info), 1));
	int i;
	int rc;
	int atype;
	bool supported_auth = false;

	if (sess->username[0] == 0) {
		atype = NDMP_AUTH_MD5;
	}
	else {
		atype = NDMP_AUTH_NONE;
	}

	if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
		fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
		return false;
	}

	if (hdr.message_type != NDMP_MESSAGE_REPLY) {
		fprintf(stderr, "Expected a message request but got something else\n");
	}
	if (hdr.message_code != NDMP_CONFIG_GET_SERVER_INFO) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_config_get_server_info_reply(&sess->xdrs, info)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	if (info->error != NDMP_NO_ERR) {
		fprintf(stderr, "The server info packet returned an error: %s\n", ndmp_print_error(info->error));
	}

	for (i=0; i < info->auth_type.auth_type_len; i++) {
		if (info->auth_type.auth_type_val[i] == atype) {
			supported_auth = true;
			break;
		}
	}

	if (!supported_auth) {
		fprintf(stderr, "The server does not provide the supported authentication mechanism\n");
		goto fail;
	}

	strncpy(sess->vendor_name, info->vendor_name, 256);
	strncpy(sess->product_name, info->product_name, 256);
	strncpy(sess->revision_number, info->revision_number, 256);

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_server_info_reply, info);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_server_info_reply, info);
	return false;
}


bool ndmp_send_config_get_auth_attr_request(
		ndmp_session *sess)
{
	ndmp_config_get_auth_attr_request attr;
	if (sess->username[0] == 0) {
		attr.auth_type = NDMP_AUTH_NONE;
	}
	else {
		attr.auth_type = NDMP_AUTH_MD5;
	}

	if (!ndmp_header_send(sess, NDMP_CONFIG_GET_AUTH_ATTR)) {
		return false;
	}

	if (!xdr_ndmp_config_get_auth_attr_request(&sess->xdrs, &attr)) {
		return false;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		return false;
	}
	return true;
}


bool ndmp_recv_config_get_auth_attr_reply(
		ndmp_session *sess)
{
	ndmp_header hdr;
	ndmp_config_get_auth_attr_reply *attr;
	ON_ERR("memory allocation error", attr = calloc(sizeof(*attr), 1));
	int i;
	int rc;
	bool supported_auth = false;

	if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
		fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
		return false;
	}

	if (hdr.message_type != NDMP_MESSAGE_REPLY) {
		fprintf(stderr, "Expected a message request but got something else\n");
	}
	if (hdr.message_code != NDMP_CONFIG_GET_AUTH_ATTR) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_config_get_auth_attr_reply(&sess->xdrs, attr)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	if (attr->error != NDMP_NO_ERR) {
		fprintf(stderr, "The server attribute packet returned an error: %s\n", ndmp_print_error(attr->error));
		goto fail;
	}

	if (sess->username[0] == 0) {
		if (attr->server_attr.auth_type != NDMP_AUTH_NONE) {
			fprintf(stderr, "The server attribute packet was expected to be for a NONE request but it was not\n");
			goto fail;
		}
	}
	else {
		if (attr->server_attr.auth_type != NDMP_AUTH_MD5) {
			fprintf(stderr, "The server attribute packet was expected to be for an MD5 request but it was not\n");
			goto fail;
		}
		memcpy(sess->challenge, attr->server_attr.ndmp_auth_attr_u.challenge, 64);
	}

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_reply, attr);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_reply, attr);
	return false;
}

bool ndmp_send_config_get_butype_info_request(
		ndmp_session *sess)
{
	if (!ndmp_header_send(sess, NDMP_CONFIG_GET_BUTYPE_INFO)) {
		return false;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		return false;
	}
	return true;
}

bool ndmp_recv_config_get_butype_info_reply(
		ndmp_session *sess)
{
	ndmp_header hdr;
	ndmp_config_get_butype_attr_reply *buinfo;
	ON_ERR("Memory allocation error", buinfo = malloc(sizeof(*buinfo)));
	int rc;

	if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
		fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
		return false;
	}

	if (hdr.message_type != NDMP_MESSAGE_REPLY) {
		fprintf(stderr, "Expected a message request but got something else\n");
	}
	if (hdr.message_code != NDMP_CONFIG_GET_BUTYPE_INFO) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_config_get_butype_attr_reply(&sess->xdrs, buinfo)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_butype_attr_reply, buinfo);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_butype_attr_reply, buinfo);
	return false;
}


bool ndmp_send_config_get_connection_type_request(
		ndmp_session *sess)
{
	if (!ndmp_header_send(sess, NDMP_CONFIG_GET_CONNECTION_TYPE)) {
		return false;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		return false;
	}
	return true;
}

bool ndmp_recv_config_get_connection_type_reply(
		ndmp_session *sess)
{
	ndmp_header hdr;
	ndmp_config_get_connection_type_reply *ctype;
	ON_ERR("Memory allocation error", ctype = malloc(sizeof(*ctype)));
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
	if (hdr.message_code != NDMP_CONFIG_GET_CONNECTION_TYPE) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_config_get_connection_type_reply(&sess->xdrs, ctype)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	if (ctype->error != NDMP_NO_ERR) {
		fprintf(stderr, "Error retrieving the connection types: %s\n", ndmp_print_error(ctype->error));
		goto fail;
	}

	for (i=0; i < ctype->addr_types.addr_types_len; i++) {
		if (ctype->addr_types.addr_types_val[i] == NDMP_ADDR_TCP) {
			success = true;
			break;
		}
	}

	if (!success) {
		fprintf(stderr, "This server does not support backing up to NDMP secondary storage\n");
		goto fail;
	}

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_connection_type_reply, ctype);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_connection_type_reply, ctype);
	return false;
}


bool ndmp_send_config_get_fs_info_request(
		ndmp_session *sess)
{
	if (!ndmp_header_send(sess, NDMP_CONFIG_GET_FS_INFO)) {
		return false;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		return false;
	}
	return true;
}

bool ndmp_recv_config_get_fs_info_reply(
		ndmp_session *sess)
{
	ndmp_header hdr;
	ndmp_config_get_fs_info_reply *fsinfo;
	ON_ERR("Memory allocation error", fsinfo = malloc(sizeof(*fsinfo)));
	int rc;
	int i, j;

	if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
		fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
		return false;
	}

	if (hdr.message_type != NDMP_MESSAGE_REPLY) {
		fprintf(stderr, "Expected a message request but got something else\n");
	}
	if (hdr.message_code != NDMP_CONFIG_GET_FS_INFO) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_config_get_fs_info_reply(&sess->xdrs, fsinfo)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	if (fsinfo->error != NDMP_NO_ERR) {
		fprintf(stderr, "An error occurred retrieving filesystem info: %s\n", ndmp_print_error(fsinfo->error));
		goto fail;
	}

	sess->fslist = calloc(sizeof(*sess->fslist), fsinfo->fs_info.fs_info_len);
	if (sess->fslist == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		goto fail;
	}
	sess->fslist_len = fsinfo->fs_info.fs_info_len;

	for (i=0; i < fsinfo->fs_info.fs_info_len; i++) {
		ndmp_fs_info *t = &fsinfo->fs_info.fs_info_val[i];
		sess->fslist[i].unsupported = t->unsupported;
		QUAD_TO_U64(sess->fslist[i].total_size, t->total_size);
		QUAD_TO_U64(sess->fslist[i].used_size, t->used_size);
		QUAD_TO_U64(sess->fslist[i].used_size, t->avail_size);
      QUAD_TO_U64(sess->fslist[i].total_inodes, t->total_inodes);
      QUAD_TO_U64(sess->fslist[i].used_inodes, t->used_inodes);

		strncpy(sess->fslist[i].fs_type, t->fs_type, 16);
		strncpy(sess->fslist[i].fs_logical_device, t->fs_logical_device, 256);
		strncpy(sess->fslist[i].fs_physical_device, t->fs_physical_device, 256);

		sess->fslist[i].metadata = calloc(t->fs_env.fs_env_len, sizeof(*sess->fslist->metadata));
		sess->fslist[i].metadata_len = t->fs_env.fs_env_len;
		for (j=0; j < t->fs_env.fs_env_len; j++) {
			strncpy(sess->fslist[i].metadata[j].name, t->fs_env.fs_env_val[j].name, 256);
         strncpy(sess->fslist[i].metadata[j].value, t->fs_env.fs_env_val[j].value, 256);
		}
	}

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_fs_info_reply, fsinfo);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_config_get_fs_info_reply, fsinfo);
	return false;
}

