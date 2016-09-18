#ifndef _NDMP_COMMOBN_H
#define _NDMP_COMMON_H
#include "ndmp.h"

#define NDMP_VER 4
#define NDMPSRV_PORT "10000"
#define NDMPBACKUP_PORT_START 10001
#define NDMPBACKUP_PORT_END 20000

#define QUAD_TO_U64(target, source) \
	*(uint32_t *)(&target+1) = source.high; \
	*(uint32_t *)&target = source.low;

struct ndmp_sess {
	int fd;
	int seqno;
	bool connected;
	bool authenticated;
	uint32_t protocol;
	XDR xdrs;

	char peername[256];
	char peerport[64];
	char username[256];
	char password[256];
	char challenge[64];

	char vendor_name[256];
	char product_name[256];
	char revision_number[256];

	int fslist_len;
	struct fsinfo_node {
		long unsupported;
		char fs_type[16];
		char fs_logical_device[256];
		char fs_physical_device[256];
		char status[256];
		uint64_t total_size;
		uint64_t used_size;
		uint64_t avail_size;
		uint64_t total_inodes;
		uint64_t used_inodes;
		int metadata_len;
		struct envs {
			char name[256];
			char value[256];
		} *metadata;
	} *fslist;
};

typedef struct ndmp_sess ndmp_session;

extern char *ndmp_print_error(ndmp_error error_code);
extern ndmp_session * ndmp_connect(char *host, char *port, char *user, char *pass);
extern void ndmp_disconnect(ndmp_session *sess);

bool ndmp_send_config_get_server_info_request(ndmp_session *sess);
bool ndmp_recv_config_get_server_info_reply(ndmp_session *sess);
bool ndmp_send_config_get_auth_attr_request(ndmp_session *sess);
bool ndmp_recv_config_get_auth_attr_reply(ndmp_session *sess);

bool ndmp_send_config_get_butype_info_reply(ndmp_session *sess);
bool ndmp_recv_config_get_butype_info_reply(ndmp_session *sess);
bool ndmp_send_config_get_connection_type_request(ndmp_session *sess);
bool ndmp_recv_config_get_connection_type_reply(ndmp_session *sess);
bool ndmp_send_config_get_fs_info_request(ndmp_session *sess);
bool ndmp_recv_config_get_fs_info_reply(ndmp_session *sess);

bool ndmp_send_data_connect_request(ndmp_session *sess);
bool ndmp_recv_data_connect_reply(ndmp_session *sess);

#endif
