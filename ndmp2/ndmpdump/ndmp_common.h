#ifndef _NDMP_COMMON_H
#define _NDMP_COMMON_H
#include "ndmp.h"
#include "ndmp_error.h"
#include <sys/epoll.h>

#define NDMP_VER 4
#define NDMPSRV_PORT "10000"
#define NDMPBACKUP_PORT_START 10001
#define NDMPBACKUP_PORT_END 20000

#define NDMP_DEFAULT_BLOCK_SZ 4096

#define QUAD_TO_U64(target, source) \
   memcpy(&target, &source, 8);


#define REPLY_HEADER_CHECKS(msgcode)\
   int _reply_hdr_chk_rc; \
   ndmp_header hdr; \
   memset(&hdr, 0, sizeof(hdr)); \
   if ((_reply_hdr_chk_rc = ndmp_header_recv(sess, &hdr)) != 1) \
      goto fail; \
\
   if (hdr.message_type != NDMP_MESSAGE_REPLY) \
      SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_NOT_REPLY, fail); \
\
   if (hdr.message_code != msgcode) \
      SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_BAD_MESSAGECODE, fail); \
\
   if (sess->seqno != hdr.reply_sequence) \
      SET_ERR(sess, MAJ_HEADER_ERROR, MIN_HEADER_BAD_SEQNO, fail);

typedef struct ndmp_callback ndmp_callback;
typedef struct ndmp_sess ndmp_session;
typedef struct ndmp_server_info ndmp_server_info;
typedef struct ndmp_env ndmp_env;
typedef struct fsinfo fsinfo;
typedef struct buinfo buinfo;

#include "ndmp_mover.h"

enum ndmp_event {
   NDMP_IN = EPOLLIN|EPOLLPRI,
   NDMP_OUT = EPOLLOUT,
   NDMP_BOTH = EPOLLIN|EPOLLPRI | EPOLLOUT
};

struct ndmp_sess {
   int poll;
   int numfds;
   int fd;
   int seqno;
   int peer_seqno;
   XDR xdrs;

   char username[64];
   char password[64];
   char peerhost[256];
   char peerport[32];
   char moverhost[256];
   char moverport[32];

   int err_major;
   int err_minor;
   char *err_text;

   int fs_len;
   fsinfo *fs;

   int bu_len;
   buinfo *bu;

   ndmp_error error;
   mover_state *mover;
};

struct ndmp_callback {
   struct ndmp_sess *sess;
   int fd;
   bool (*callback)(struct ndmp_sess *sess);
};

struct ndmp_server_info {
   char vendor_name[256];
   char product_name[256];
   char revision_number[256];
};

struct ndmp_env {
   char name[256];
   char value[256];
};

struct fsinfo {
  uint32_t unsupported;
  char *fstype;
  char *mountpoint;
  char *device;
  uint64_t size;
  uint64_t used;
  uint64_t free;
  uint64_t inodes;
  uint64_t used_inodes;
  char *status;
  int env_len;
  ndmp_env *envs;
};

struct buinfo {
   char *name;
   int env_len;
   ndmp_env *envs;
   int attrs;
};

/* ndmp_common */
ndmp_session * ndmp_init_session();
void ndmp_destroy_session(ndmp_session *sess);

/* dispatcher */
bool ndmp_dma_dispatcher(ndmp_session *sess);


/* Connect */
ndmp_session * ndmp_init_session();
bool ndmp_connect(ndmp_session *sess, char *host, char *port, char *user, char *pass);
void ndmp_disconnect(ndmp_session *sess);

/* Config */
bool ndmp_get_server_info(ndmp_session *sess, ndmp_server_info *info);
bool ndmp_get_challenge(ndmp_session *sess, char challenge[64]);
bool ndmp_get_fsinfo(ndmp_session *sess);
bool ndmp_get_buinfo(ndmp_session *sess);

/* Error */
void ndmp_print_errror(ndmp_session *sess, char *buf, int len);
/*

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
*/
#endif
