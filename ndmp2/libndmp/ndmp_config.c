#include "common.h"
#include "ndmp.h"
#include "ndmp_common.h"

static bool ndmp_send_config_get_server_info_request(ndmp_session *sess);
static bool ndmp_recv_config_get_server_info_reply(ndmp_session *sess, ndmp_server_info *info);
static bool ndmp_recv_config_get_auth_attr_reply(ndmp_session *sess, char challenge[64]);
static bool ndmp_send_config_get_auth_attr_request(ndmp_session *sess);
static bool ndmp_send_config_get_fs_info_request(ndmp_session *sess);
static bool ndmp_recv_config_get_fs_info_reply(ndmp_session *sess);
static bool ndmp_send_config_get_butype_attr_request(ndmp_session *sess);
static bool ndmp_recv_config_get_butype_attr_reply(ndmp_session *sess);
static bool ndmp_fs_info_to_local_fsinfo(fsinfo *fs, ndmp_fs_info *fsinfo);
static bool ndmp_bu_info_to_local_buinfo(buinfo *bu, ndmp_butype_info *buinfo);

/* Translate ndmp specific bu info data to our own version fo buinfo data */
static bool ndmp_bu_info_to_local_buinfo(
      buinfo *bu, 
      ndmp_butype_info *buinfo)
{
   int i;
   bu->name = strdup(buinfo->butype_name);
   if (!bu->name)
     return false;

   bu->env_len = buinfo->default_env.default_env_len;
   bu->envs = calloc(bu->env_len, sizeof(*bu->envs));
   if (!bu->envs)
      return false;

   for (i=0; i < bu->env_len; i++) { 
      strncpy(bu->envs[i].name, buinfo->default_env.default_env_val[i].name, 256);
      strncpy(bu->envs[i].value, buinfo->default_env.default_env_val[i].value, 256);
   }
   return true;
}

/* Translate ndmp specific fs info data to our own version of fsinfo data */
static bool ndmp_fs_info_to_local_fsinfo(
      fsinfo *fs,
      ndmp_fs_info *fsinfo)
{
   int i;
   fs->unsupported = fsinfo->unsupported;
   QUAD_TO_U64(fs->size, fsinfo->total_size);
   QUAD_TO_U64(fs->used, fsinfo->used_size);
   QUAD_TO_U64(fs->free, fsinfo->avail_size);
   QUAD_TO_U64(fs->inodes, fsinfo->total_inodes);
   QUAD_TO_U64(fs->used_inodes, fsinfo->used_inodes);

   fs->fstype = strdup(fsinfo->fs_type);
   fs->mountpoint = strdup(fsinfo->fs_logical_device);
   fs->device = strdup(fsinfo->fs_physical_device);
   if (!fs->device || !fs->mountpoint || !fs->device)
      return false;

   fs->env_len = fsinfo->fs_env.fs_env_len;
   fs->envs = calloc(fsinfo->fs_env.fs_env_len, sizeof(*fs->envs));
   if (!fs->envs)
      return false;

   for (i=0; i < fsinfo->fs_env.fs_env_len; i++) {
      strncpy(fs->envs[i].name, fsinfo->fs_env.fs_env_val[i].name, 256);
      strncpy(fs->envs[i].value, fsinfo->fs_env.fs_env_val[i].value, 256);
   }
   return true;
}

/* Receive server info packet. Can return null data when not authenticated */
bool ndmp_get_server_info(
      ndmp_session *sess,
      ndmp_server_info *info)
{
   assert(sess);
   assert(info);

   if (!ndmp_send_config_get_server_info_request(sess))
      goto fail;
   if (!ndmp_recv_config_get_server_info_reply(sess, info))
      goto fail;
   return true;
fail:
   return false;
}


/* Get a challenge blob to be used for md5 authentication */
bool ndmp_get_challenge(
      ndmp_session *sess,
      char challenge[64])
{
   assert(sess);
   assert(challenge);

   if (!ndmp_send_config_get_auth_attr_request(sess))
      goto fail;
   if (!ndmp_recv_config_get_auth_attr_reply(sess, challenge))
      goto fail;

   return true;
fail:
   return false;
}

/* Get all filesystem info */
bool ndmp_get_fsinfo(
      ndmp_session *sess)
{
   assert(sess);

   if (!ndmp_send_config_get_fs_info_request(sess))
      goto fail;
   if (!ndmp_recv_config_get_fs_info_reply(sess))
      goto fail;

   return true;
fail:
   return false;
}

/* Get all backup info */
bool ndmp_get_buinfo(
      ndmp_session *sess)
{
   assert(sess);

   if (!ndmp_send_config_get_butype_attr_request(sess))
      goto fail;
   if (!ndmp_recv_config_get_butype_attr_reply(sess))
      goto fail;

   return true;
fail:
   return false;
}


static bool ndmp_send_config_get_server_info_request(
      ndmp_session *sess)
{
   assert(sess);

   if (!ndmp_header_send(sess, NDMP_CONFIG_GET_SERVER_INFO))
      goto fail;
   if (!xdrrec_endofrecord(&sess->xdrs, 1))
      SET_ERR(sess, MAJ_CONFIG_ERROR, SERVER_INFO_ENCODE, fail);

   return true;

fail:
   return false;
}

/* Discover if server supports md5 authentication and fill in any other data
 * necessary */
static bool ndmp_recv_config_get_server_info_reply(
      ndmp_session *sess,
      ndmp_server_info *in)
{
   ndmp_config_get_server_info_reply reply;
   memset(&reply, 0, sizeof(reply));
   int i;
   int rc;
   int atype;
   bool supported_auth = false;

   if (sess->username[0] == 0) 
      atype = NDMP_AUTH_NONE;
   else 
      atype = NDMP_AUTH_MD5;

   REPLY_HEADER_CHECKS(NDMP_CONFIG_GET_SERVER_INFO);

   sess->xdrs.x_op = XDR_DECODE;   
   if (!xdr_ndmp_config_get_server_info_reply(&sess->xdrs, &reply))
      SET_ERR(sess, MAJ_CONFIG_ERROR, SERVER_INFO_DECODE, fail);

   sess->error = reply.error;
   if (reply.error != NDMP_NO_ERR)
      SET_ERR(sess, MAJ_HEADER_ERROR, reply.error, fail);

   for (i=0; i < reply.auth_type.auth_type_len; i++) {
      if (reply.auth_type.auth_type_val[i] == atype) {
         supported_auth = true;
         break;
      }
   }

   if (!supported_auth)
      SET_ERR(sess, MAJ_CONFIG_ERROR, UNSUPPORTED_AUTH, fail);

   strncpy(in->vendor_name, reply.vendor_name, 256);
   strncpy(in->product_name, reply.product_name, 256);
   strncpy(in->revision_number, reply.revision_number, 256);

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_server_info_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_server_info_reply, &reply);
   return false;
}


static bool ndmp_send_config_get_auth_attr_request(
      ndmp_session *sess)
{
   assert(sess);

   ndmp_config_get_auth_attr_request attr;
   if (sess->username[0] == 0) {
      attr.auth_type = NDMP_AUTH_NONE;
   }
   else {
      attr.auth_type = NDMP_AUTH_MD5;
   }

   if (!ndmp_header_send(sess, NDMP_CONFIG_GET_AUTH_ATTR))
      goto fail;
   if (!xdr_ndmp_config_get_auth_attr_request(&sess->xdrs, &attr))
      SET_ERR(sess, MAJ_CONFIG_ERROR, GET_AUTH_ENCODE, fail);

   if (!xdrrec_endofrecord(&sess->xdrs, 1))
      SET_ERR(sess, MAJ_HEADER_ERROR, SEND_ERROR, fail);

   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_request, &attr);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_request, &attr);
   return false;
}


static bool ndmp_recv_config_get_auth_attr_reply(
      ndmp_session *sess,
      char challenge[64])
{
   assert(sess);
   assert(challenge);

   ndmp_config_get_auth_attr_reply reply;
   memset(&reply, 0, sizeof(reply));
   int i;
   int rc;
   bool supported_auth = false;

   REPLY_HEADER_CHECKS(NDMP_CONFIG_GET_AUTH_ATTR);

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_config_get_auth_attr_reply(&sess->xdrs, &reply))
      SET_ERR(sess, MAJ_CONFIG_ERROR, GET_AUTH_DECODE, fail);

   sess->error = reply.error;
   if (reply.error != NDMP_NO_ERR)
      SET_ERR(sess, MAJ_HEADER_ERROR, reply.error, fail);

   if (sess->username[0] == 0) {
      if (reply.server_attr.auth_type != NDMP_AUTH_NONE)
         SET_ERR(sess, MAJ_CONFIG_ERROR, AUTH_MECH_CONTRADICTION, fail);
   }
   else {
      if (reply.server_attr.auth_type != NDMP_AUTH_MD5)
         SET_ERR(sess, MAJ_CONFIG_ERROR, AUTH_MECH_CONTRADICTION, fail);
      memcpy(challenge, reply.server_attr.ndmp_auth_attr_u.challenge, 64);
   }

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_reply, &reply);
   return false;
}


bool ndmp_send_config_get_fs_info_request(
      ndmp_session *sess)
{
   if (!ndmp_header_send(sess, NDMP_CONFIG_GET_FS_INFO)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1))
      SET_ERR(sess, MAJ_CONFIG_ERROR, FSINFO_ENCODE, fail);

   return true;

fail:
   return false;
}


static bool ndmp_recv_config_get_fs_info_reply(
      ndmp_session *sess)
{
   assert(sess);
   int i;
   ndmp_config_get_fs_info_reply reply;
   memset(&reply, 0, sizeof(reply));

   REPLY_HEADER_CHECKS(NDMP_CONFIG_GET_FS_INFO);

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_config_get_fs_info_reply(&sess->xdrs, &reply))
      SET_ERR(sess, MAJ_CONFIG_ERROR, FSINFO_DECODE, fail);

   if (reply.error != NDMP_NO_ERR)
      SET_ERR(sess, MAJ_HEADER_ERROR, reply.error, fail);

   /* We destroy the old config if it exists */
   if (sess->fs) {
      for (i=0; i < sess->fs_len; i++) {
        if (sess->fs[i].envs)
          free(sess->fs[i].envs);
      }
      free(sess->fs);
      sess->fs = NULL;
   }

   sess->fs_len = reply.fs_info.fs_info_len;
   sess->fs = calloc(sess->fs_len, sizeof(*sess->fs));
   if (!sess)
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);

   /* Now loop over each record and copy the data into the fsinfo
    * structure */
   for (i=0; i < sess->fs_len; i++) {
      if (!ndmp_fs_info_to_local_fsinfo(&sess->fs[i], &reply.fs_info.fs_info_val[i]))
         SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
   }
   
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_fs_info_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_fs_info_reply, &reply);
   return false;
}


bool ndmp_send_config_get_butype_attr_request(
      ndmp_session *sess)
{
   if (!ndmp_header_send(sess, NDMP_CONFIG_GET_BUTYPE_INFO)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1))
      SET_ERR(sess, MAJ_CONFIG_ERROR, BUINFO_ENCODE, fail);

   return true;

fail:
   return false;
}



static bool ndmp_recv_config_get_butype_attr_reply(
      ndmp_session *sess)
{
   assert(sess);
   int i;
   ndmp_config_get_butype_attr_reply reply;
   memset(&reply, 0, sizeof(reply));

   REPLY_HEADER_CHECKS(NDMP_CONFIG_GET_BUTYPE_INFO);

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_config_get_butype_attr_reply(&sess->xdrs, &reply))
      SET_ERR(sess, MAJ_CONFIG_ERROR, BUINFO_DECODE, fail);

   if (reply.error != NDMP_NO_ERR)
      SET_ERR(sess, MAJ_HEADER_ERROR, reply.error, fail);

   /* We destroy the old config if it exists */
   if (sess->bu) {
      for (i=0; i < sess->bu_len; i++) {
        if (sess->bu[i].envs)
          free(sess->bu[i].envs);
      }
      free(sess->bu);
      sess->bu = NULL;
   }

   sess->bu_len = reply.butype_info.butype_info_len;
   sess->bu = calloc(sess->bu_len, sizeof(*sess->bu));
   if (!sess)
      SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);

   /* Now loop over each record and copy the data into the fsinfo
    * structure */
   for (i=0; i < sess->bu_len; i++) {
      if (!ndmp_bu_info_to_local_buinfo(&sess->bu[i], &reply.butype_info.butype_info_val[i]))
         SET_ERR(sess, MAJ_SYSTEM_ERROR, errno, fail);
   }
   
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_butype_attr_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_butype_attr_reply, &reply);
   return false;
}


/*
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
*/
