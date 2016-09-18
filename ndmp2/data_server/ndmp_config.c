#include "common.h"
#include "ndmp_common.h"

#include <mntent.h>
#include <sys/vfs.h>

static bool create_random_string(char *str);
static int create_fs_info_table(ndmp_fs_info **fsinfo);
static int create_butype_info_table(ndmp_butype_info **buinfo);
static void destroy_fs_info_table(ndmp_fs_info *fsinfo);

static bool ndmp_send_config_get_server_info_reply(ndmp_session *sess, bool show);
static bool ndmp_send_config_get_auth_attr_reply(ndmp_session *sess, ndmp_auth_type auth_type);
static bool ndmp_send_config_get_connection_type_reply(ndmp_session *sess);
static bool ndmp_send_config_get_fs_info_reply(ndmp_session *sess);
static bool ndmp_send_config_get_butype_info_reply(ndmp_session *sess);

static bool create_random_string(
		char *str)
{
	FILE *f = fopen("/dev/urandom", "r");
	if (!f)
		return false;

	if (fread(str, 64, 1, f) <= 0)
		goto fail;

	fclose(f);
	return true;

fail:
	if (f)
		fclose(f);
	return false;
}

static int create_butype_info_table(
		ndmp_butype_info **buinfo)
{
	ndmp_butype_info *info;
	ndmp_pval *env;
	struct mntent *mnt;
	FILE *mtab = NULL;

	info = calloc(sizeof(*info), 1);
   info[0].butype_name = strdup("dump");
   info[0].attrs = NDMP_BUTYPE_BACKUP_INCREMENTAL | NDMP_BUTYPE_BACKUP_FH_FILE | NDMP_BUTYPE_BACKUP_FH_DIR;
	info[0].default_env.default_env_len = 12;
	info[0].default_env.default_env_val = calloc(sizeof(*info[0].default_env.default_env_val), 12);

	env = info[0].default_env.default_env_val;
	env[0].name = strdup("FILESYSTEM");
	//env[0].value = strdup("/dev/sda1");
//	env[0].value = strdup("/dev/mapper/sys0-root--overlay");
   env[0].value = strdup("/dev/loop0");
	env[1].name = strdup("DIRECT");
	env[1].value = strdup("n");
	env[2].name = strdup("RECURSIVE");
	env[2].value = strdup("y");
	env[3].name = strdup("TYPE");
	env[3].value = strdup("dump");
	env[4].name = strdup("USER");
	env[4].value = strdup("root");
	env[5].name = strdup("HIST");
	env[5].value = strdup("f");
	env[6].name = strdup("PATHNAME_SEPARATOR");
	env[6].value = strdup("/");
	env[7].name = strdup("LEVEL");
	env[7].value = strdup("0");
	env[8].name = strdup("EXTRACT");
	env[8].value = strdup("y");
	env[9].name = strdup("UPDATE");
	env[9].value = strdup("n");
	env[10].name = strdup("READ_BLOCK_SIZE");
	env[10].value = strdup("8192");
	env[11].name = strdup("WRITE_BLOCK_SIZE");
	env[11].value = strdup("8192");

	*buinfo = info;
	return 1;

fail:
	xdr_free((xdrproc_t)xdr_ndmp_butype_info, info);
	if (mtab) fclose(mtab);
	return -1;
}

static int create_fs_info_table(ndmp_fs_info **fsinfo)
{
	int len=0, i=0;
	uint64_t num;
	ndmp_fs_info *info;
	struct statfs stat;
	struct mntent *mnt;

	FILE *mtab = fopen("/etc/mtab", "r");
	if (mtab == NULL) {
		fprintf(stderr, "Error obtaining mtab: %s\n", strerror(errno));
		goto fail;
	}

	while ((mnt = getmntent(mtab)) != NULL) {
		if (strncmp(mnt->mnt_type, "ext", 3) != 0) 
			continue;
		len++;
	}
	rewind(mtab);

	info = calloc(sizeof(*info), len);
	while ((mnt = getmntent(mtab)) != NULL) {
		if (strncmp(mnt->mnt_type, "ext", 3) != 0)
			continue;
		memset(&stat, 0, sizeof(stat));
		if (statfs(mnt->mnt_dir, &stat) < 0) {
			fprintf(stderr, "Error getting statfs for filesystem: %s\n", strerror(errno));
			info = realloc(info, sizeof(*info) * --len);
			i++;
			continue;
		}
		info[i].unsupported = 0;
		info[i].fs_status = strdup("online");
		info[i].fs_type = strdup(mnt->mnt_type);
		info[i].fs_logical_device = strdup(mnt->mnt_dir);
		info[i].fs_physical_device = strdup(mnt->mnt_fsname);
		num = stat.f_blocks * stat.f_bsize;
		U64_TO_QUAD(info[i].total_size, num);
		num = (stat.f_blocks - stat.f_bfree) * stat.f_bsize;
		U64_TO_QUAD(info[i].used_size, num);
		num = stat.f_bavail * stat.f_bsize;
		U64_TO_QUAD(info[i].avail_size, num);
		num = stat.f_files;
		U64_TO_QUAD(info[i].total_inodes, num);
		num = stat.f_files - stat.f_ffree;
		U64_TO_QUAD(info[i].used_inodes, num);

		info[i].fs_env.fs_env_len = 4;
		info[i].fs_env.fs_env_val = calloc(sizeof(*info[i].fs_env.fs_env_val), 4);

		info[i].fs_env.fs_env_val[0].name = strdup("TYPE");
		info[i].fs_env.fs_env_val[0].value = strdup(mnt->mnt_type);
		info[i].fs_env.fs_env_val[1].name = strdup("AVAILABLE_BACKUP");
		info[i].fs_env.fs_env_val[1].value = strdup("dump");
		info[i].fs_env.fs_env_val[2].name = strdup("AVAILABLE_RECOVERY");
		info[i].fs_env.fs_env_val[2].value = strdup("dump");
      info[i].fs_env.fs_env_val[3].name = strdup("LOCAL");
      info[i].fs_env.fs_env_val[3].value = strdup("y");
		i++;
	}

	*fsinfo = info;
	fclose(mtab);
	return len;

fail:
	destroy_fs_info_table(info);
	if (mtab) fclose(mtab);
	return -1;
}

static void destroy_fs_info_table(
		ndmp_fs_info *info)
{
	xdr_free((xdrproc_t)xdr_ndmp_fs_info, info);
}
	
bool ndmp_recv_config_get_server_info_request(
      ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_config_get_server_info_reply(sess, sess->connected))
      goto fail;

   return true;

fail:
   return false;
}


static bool ndmp_send_config_get_server_info_reply(
      ndmp_session *sess,
      bool show)
{
   ndmp_config_get_server_info_reply reply ;
	memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_CONFIG_GET_SERVER_INFO))
      goto fail;

   sess->xdrs.x_op = XDR_ENCODE;
   reply.error = NDMP_NO_ERR;
   if (show) {
      reply.product_name = strdup(sess->product_name);
      reply.vendor_name = strdup(sess->vendor_name);
      reply.revision_number = strdup(sess->revision_number);
   }
   else {
      reply.product_name = strdup("");
      reply.vendor_name = strdup("");
      reply.revision_number = strdup("");
   }

#ifdef SUPPORT_AUTH_NONE
   reply.auth_type.auth_type_val = calloc(sizeof(*reply.auth_type.auth_type_val), 2);
   reply.auth_type.auth_type_len = 2;
   reply.auth_type.auth_type_val[0] = NDMP_AUTH_NONE;
   reply.auth_type.auth_type_val[1] = NDMP_AUTH_MD5;
#else
   reply.auth_type.auth_type_val = calloc(sizeof(*reply.auth_type.auth_type_val), 1);
   reply.auth_type.auth_type_len = 1;
   reply.auth_type.auth_type_val[0] = NDMP_AUTH_MD5;
#endif

   if (!xdr_ndmp_config_get_server_info_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_config_get_server_info_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_config_get_server_info_reply, &reply);
   return false;
}


bool ndmp_recv_config_get_auth_attr_request(
		ndmp_session *sess)
{
   ndmp_config_get_auth_attr_request attr;
	memset(&attr, 0, sizeof(attr));

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_config_get_auth_attr_request(&sess->xdrs, &attr)) {
      goto fail;
   }
   xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_config_get_auth_attr_reply(sess, attr.auth_type))
      goto fail;

   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_request, &attr);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_request, &attr);
   return false;
}


static bool ndmp_send_config_get_auth_attr_reply(
		ndmp_session *sess,
		ndmp_auth_type auth_type)
{
   ndmp_config_get_auth_attr_reply reply;
	memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_CONFIG_GET_AUTH_ATTR))
      goto fail;

   sess->xdrs.x_op = XDR_ENCODE;
#ifdef SUPPORT_AUTH_NONE
	if (auth_type != NDMP_AUTH_NONE || auth_type != NDMP_AUTH_MD5) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		reply.server_attr.auth_type = auth_type;
	}
#else
   if (auth_type != NDMP_AUTH_MD5) {
      reply.error = NDMP_ILLEGAL_ARGS_ERR;
      reply.server_attr.auth_type = auth_type;
	}
#endif

	reply.server_attr.auth_type = auth_type;
	if (auth_type == NDMP_AUTH_MD5) {
		reply.error = NDMP_NO_ERR;
		if (!create_random_string(sess->challenge)) {
			fprintf(stderr, "Attempting to create random string failed: %s\n", strerror(errno));
			goto fail;
		}
		memcpy(reply.server_attr.ndmp_auth_attr_u.challenge, sess->challenge, 64);
	}

   if (!xdr_ndmp_config_get_auth_attr_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_config_get_auth_attr_reply, &reply);
   return false;
}


bool ndmp_recv_config_get_connection_type_request(
		ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_config_get_connection_type_reply(sess))
      goto fail;

   return true;

fail:
   return false;
}

static bool ndmp_send_config_get_connection_type_reply(
		ndmp_session *sess)
{
   ndmp_config_get_connection_type_reply reply;
	memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_CONFIG_GET_CONNECTION_TYPE))
      goto fail;

	reply.error = NDMP_NO_ERR;
	reply.addr_types.addr_types_len = 1;
	reply.addr_types.addr_types_val = calloc(sizeof(*reply.addr_types.addr_types_val), 1);
	reply.addr_types.addr_types_val[0] = NDMP_ADDR_TCP;

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_config_get_connection_type_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_config_get_connection_type_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_config_get_connection_type_reply, &reply);
   return false;
}


bool ndmp_recv_config_get_fs_info_request(
		ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_config_get_fs_info_reply(sess))
      goto fail;

   return true;

fail:
   return false;
}


static bool ndmp_send_config_get_fs_info_reply(
	ndmp_session *sess)
{
	int len=0;
	ndmp_fs_info *fsinfo = NULL;
   ndmp_config_get_fs_info_reply reply;
	memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_CONFIG_GET_FS_INFO))
      goto fail;

   reply.error = NDMP_NO_ERR;
	reply.fs_info.fs_info_len = create_fs_info_table(&reply.fs_info.fs_info_val);

	if (len < 0) {
		fprintf(stderr, "There was a problem getting filesystem info\n");
		goto fail;
	}

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_config_get_fs_info_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_config_get_fs_info_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_config_get_fs_info_reply, &reply);
   return false;
}


bool ndmp_recv_config_get_butype_info_request(
		ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_config_get_butype_info_reply(sess))
      goto fail;

   return true;

fail:
   return false;
}


static bool ndmp_send_config_get_butype_info_reply(
		ndmp_session *sess)
{
	int len;
   ndmp_config_get_butype_attr_reply reply;
	memset(&reply, 0, sizeof(reply));
	ndmp_butype_info *butypes = NULL;

   if(!ndmp_header_send_reply(sess, NDMP_CONFIG_GET_BUTYPE_INFO))
      goto fail;

	reply.error = NDMP_NO_ERR;
	len = create_butype_info_table(&butypes);
	reply.butype_info.butype_info_len = len;
	reply.butype_info.butype_info_val = butypes;

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_config_get_butype_attr_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_config_get_butype_attr_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_config_get_butype_attr_reply, &reply);
   return false;
}

