#ifndef _NDMP_COMMOBN_H
#define _NDMP_COMMON_H

#include <sys/epoll.h>
#include "ndmp.h"

#define NDMP_VER 4
#define NDMPSRV_PORT "10000"

//#define SUPPORT_AUTH_NONE

#define QUAD_TO_U64(target, source) \
	memcpy(&target, &source, 8);

#define U64_TO_QUAD(target ,source) \
	memcpy(&target, &source, 8);
	//target.low = *(uint32_t *)(&source); \
	//target.high = *(uint32_t *)(&source)+1;

enum ndmp_event {
	NDMP_IN = EPOLLIN|EPOLLPRI,
	NDMP_OUT = EPOLLOUT,
	NDMP_BOTH = EPOLLIN|EPOLLPRI | EPOLLOUT
};

struct envs {
	char name[256];
	char value[256];
};

struct state_addr {
   uint32_t ip;
   uint16_t port;
};

struct ndmp_sess {
	int poll;
	int signalfd;
	int pipe;
	int epipe;
	int fd;
	int backup_fd;
	int seqno;
	int peer_seqno;
	pid_t dumper_pid;
	bool connected;
	bool authenticated;
	uint32_t protocol;
	XDR xdrs;

	struct {
		int time_remaining;
		uint64_t bytes_remaining;
		uint64_t bytes_processed;
		uint64_t read_offset;
		uint64_t read_length;
		enum ndmp_data_operation operation;
		enum ndmp_data_state data_state;
		enum ndmp_data_halt_reason halt_reason;
		struct state_addr addr;
		int peer_env_len;
		struct envs *peer_env;
	} state;
	
	char peername[256];
	char peerport[64];
	char username[256];
	char password[256];
	char challenge[64];

	char vendor_name[256];
	char product_name[256];
	char revision_number[256];

};

struct ndmp_callback {
   struct ndmp_sess *sess;
	int fd;
   bool (*callback)(struct ndmp_sess *sess);
};

typedef struct ndmp_callback ndmp_callback;
typedef struct ndmp_sess ndmp_session;
typedef struct state_addr state_addr;
ndmp_session * ndmp_init_session(int fd);

bool ndmp_header_authorisation_required(ndmp_message message_code);

void ndmp_disconnect(ndmp_session *sess);
bool ndmp_send_notify_connection_status(ndmp_session *sess, ndmp_connection_status_reason status, char *reason);

bool ndmp_data_server_dispatcher(ndmp_session *sess);
bool ndmp_dispatcher_add_fd(ndmp_session *sess, int fd, enum ndmp_event event, bool (*callback)(ndmp_session *));
bool ndmp_dispatcher_mod_fd(ndmp_session *sess, int fd, enum ndmp_event event, bool (*callback)(ndmp_session *));
bool ndmp_dispatcher_del_fd(ndmp_session *sess, int fd);

bool ndmp_recv_connect_open_request(ndmp_session *sess);
bool ndmp_recv_connect_client_auth_request(ndmp_session *sess);

bool ndmp_recv_config_get_server_info_request(ndmp_session *sess);
bool ndmp_recv_config_get_auth_attr_request(ndmp_session *sess);
bool ndmp_recv_config_get_connection_type_request(ndmp_session *sess);
bool ndmp_recv_config_get_butype_info_request(ndmp_session *sess);

bool ndmp_recv_data_connect_request(ndmp_session *sess);
bool ndmp_recv_data_start_backup_request(ndmp_session *sess);
bool ndmp_recv_data_get_state_request(ndmp_session *sess);
bool ndmp_send_notify_data_halted_post(ndmp_session *sess, ndmp_data_halt_reason why);
bool ndmp_recv_data_get_env_request(ndmp_session *sess);
bool ndmp_recv_data_abort_request(ndmp_session *sess);
bool ndmp_recv_data_stop_Request(ndmp_session *sess);

bool ndmp_send_log_message_post(ndmp_session *sess, ndmp_log_type type, char *message);

extern char *ndmp_print_error(ndmp_error error_code);
#endif
