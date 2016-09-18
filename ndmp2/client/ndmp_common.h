#ifndef _NDMP_COMMOBN_H
#define _NDMP_COMMON_H
#include "ndmp.h"

#include <sys/epoll.h>

#define NDMP_VER 4
#define NDMPSRV_PORT "10000"
#define NDMPBACKUP_PORT_START 10001
#define NDMPBACKUP_PORT_END 20000

#define NDMP_MIN_BLOCK_SZ 512
#define NDMP_MAX_BLOCK_SZ 131072
#define NDMP_DEFAULT_BLOCK_SZ 4096

#define QUAD_TO_U64(target, source) \
	memcpy(&target, &source, 8);

enum ndmp_event {
   NDMP_IN = EPOLLIN|EPOLLPRI,
   NDMP_OUT = EPOLLOUT,
   NDMP_BOTH = EPOLLIN|EPOLLPRI | EPOLLOUT
};

struct state_addr {
	uint32_t ip;
	uint16_t port;
};

struct envs {
	char name[256];
	char value[256];
} *metadata;

struct ndmp_databkp {
	bool ready;
	char type[256];
	int backup_fd;
	time_t start_time;
	time_t end_time;

   enum {
      DATA_STATE_IDLE,
      DATA_STATE_LISTEN,
      DATA_STATE_CONNECTED,
      DATA_STATE_ACTIVE,
      DATA_STATE_HALTED,
   } data_state;

	uint32_t read_block_sz;
	uint32_t write_block_sz;
};

struct ndmp_sess {
	int poll;
	int fd;
	int seqno;
	int peer_seqno;
	pid_t backup_pid;
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

	struct ndmp_databkp *backup;

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
		struct envs *metadata;
	} *fslist;

	int bklist_len;

	struct bkinfo_node {
		char backup_type[256];
		uint32_t attrs;
		int metadata_len;
		struct envs *metadata;
	} *bklist;

	int peer_env_len;
	struct envs *peer_env;
};

struct ndmp_callback {
   struct ndmp_sess *sess;
   int fd;
   bool (*callback)(struct ndmp_sess *sess);
};

typedef struct ndmp_callback ndmp_callback;
typedef struct ndmp_sess ndmp_session;
typedef struct ndmp_databkp ndmp_databackup;
typedef struct state_addr state_addr;

char *ndmp_print_error(ndmp_error error_code);

ndmp_session * ndmp_init_session();
void ndmp_destroy_session(ndmp_session *sess);
ndmp_databackup * ndmp_init_databackup();
void ndmp_destroy_databackup(ndmp_databackup *backup);

bool ndmp_dma_dispatcher(ndmp_session *sess);

ndmp_session * ndmp_connect(char *host, char *port, char *user, char *pass);
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
bool ndmp_send_data_start_backup_request(ndmp_session *session, char *backup_type, struct envs *env, int envlen);
bool ndmp_recv_data_start_backup_reply(ndmp_session *sess);
void ndmp_data_disconnect(ndmp_session *sess);
bool ndmp_recv_notify_data_halted_post(ndmp_session *sess);
bool ndmp_send_data_get_state_request(ndmp_session *sess);
bool ndmp_recv_data_get_state_reply(ndmp_session *sess);
bool ndmp_send_data_get_env_request(ndmp_session *sess);
bool ndmp_recv_data_get_env_reply(ndmp_session *sess);
bool ndmp_send_data_abort_request(ndmp_session *sess);
bool ndmp_recv_data_abort_reply(ndmp_session *sess);
bool ndmp_send_data_stop_request(ndmp_session *sess);
bool ndmp_recv_data_stop_reply(ndmp_session *sess);

bool ndmp_recv_log_normal_message_post(ndmp_session *sess);

#endif
