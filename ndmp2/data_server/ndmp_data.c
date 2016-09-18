#include "common.h"
#include "ndmp_common.h"

#include <mntent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <netdb.h>

static char * get_arg(struct ndmp_pval *env, int envlen, char *key);
static void abort_dump(ndmp_session *sess);
static void stop_dump(ndmp_session *sess);
static bool spawn_dump(ndmp_session *session, struct ndmp_pval *env, int envlen);
static bool create_args_array(struct ndmp_pval *env, int envlen, char ***results);
static bool ndmp_send_data_connect_reply(ndmp_session *sess, ndmp_error error);
static bool ndmp_send_data_start_backup_reply(ndmp_session *sess, ndmp_error error);
static bool ndmp_data_read_data(ndmp_session *sess);
static bool ndmp_data_read_dataerr(ndmp_session *sess);
static bool ndmp_data_read_signal(ndmp_session *sess);
static bool ndmp_send_data_get_state_reply(ndmp_session *sess);
static bool ndmp_send_data_get_env_reply(ndmp_session *sess);
static bool ndmp_send_data_abort_reply(ndmp_session *sess, ndmp_error error);
static bool ndmp_send_data_stop_reply(ndmp_session *sess, ndmp_error error);

static char * get_arg(
		struct ndmp_pval *env,
		int envlen,
		char *key)
{
	int i;
	for (i=0; i < envlen; i++) {
		if (strcmp(key, env[i].name) == 0) {
			return env[i].value;
		}
	}
	return NULL;
}

static bool create_args_array(
		struct ndmp_pval *env,
		int envlen,
		char ***results)
{
	int i=0;
	int tmp;
	char **args = calloc(sizeof(*args), 256);
	char *arg = NULL;
	bool foundfs = false;
	struct mntent *mnt = NULL;
	FILE *mtab = NULL;

	args[i++] = strdup("dump");
//	args[i++] = strdup("-z9");
	args[i++] = strdup("-f");
	args[i++] = strdup("-");

	if (!(arg = get_arg(env, envlen, "LEVEL"))) {
		args[i++] = strdup("-0");
	}
	else {
		args[i] = calloc(16, 1);
		tmp = atoi(arg);
		snprintf(args[i], 16, "-%d", arg);
	}

	if (!(arg = get_arg(env, envlen, "FILESYSTEM"))) {
		free(arg);
		return false;
	}

	mtab = setmntent("/etc/mtab", "r");
	if (!mtab) goto fail;

	while ((mnt = getmntent(mtab))) {
		if ((strncmp(mnt->mnt_fsname, arg, 256) == 0) &&
				strncmp(mnt->mnt_type, "ext", 3) == 0) {
					foundfs = true;
		}
	}
	if (foundfs) {
		args[i++] = strdup(arg);
	}
	else {
		goto fail;
	}

	*results = args;
	endmntent(mtab);
	return true;

fail:
	if (mtab) endmntent(mtab);
	return false;
}

static void stop_dump(
		ndmp_session *sess)
{
	sess->state.operation = NDMP_DATA_OP_NOACTION;
	sess->state.data_state = NDMP_DATA_STATE_IDLE;
	sess->state.halt_reason = NDMP_DATA_HALT_NA;
	memset(&sess->state.addr, 0, sizeof(sess->state.addr));
	sess->state.peer_env_len = 0;
	free(sess->state.peer_env);
	sess->state.peer_env = NULL;
	sess->state.time_remaining = 0;
	sess->state.bytes_remaining = 0;
	sess->state.bytes_processed = 0;
	sess->state.time_remaining = 0;
	sess->state.read_offset = 0;
	sess->state.read_length = 0;

	return;
}

static void abort_dump(
		ndmp_session *sess)
{
	if (sess->dumper_pid > 0) {
		kill(sess->dumper_pid, SIGQUIT);
	}
	if (sess->backup_fd > 0) {
		shutdown(sess->backup_fd, SHUT_RDWR);
		close(sess->backup_fd);
		memset(&sess->state.addr, 0, sizeof(sess->state.addr));
	}

	if (sess->pipe > -1) { close(sess->pipe); sess->pipe = -1; }
	if (sess->epipe > -1) { close(sess->epipe); sess->epipe = -1; }
	if (sess->signalfd > -1) { close(sess->signalfd); sess->signalfd = -1; }

	sess->dumper_pid = -1;
}


static bool spawn_dump(
		ndmp_session *sess,
		struct ndmp_pval *env,
		int envlen)
{
	pid_t pid = -1;
	int sig = -1;
	int rc=0;
	int p[2] = { -1, -1 };
	int e[2] = { -1, -1 };
	char **args = NULL;
   sigset_t sigset;
   sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGPIPE);

	/* Must do this outside of fork so that its ready when fork occurs */
	if ((sig = signalfd(sig, &sigset, SFD_CLOEXEC)) < 0) {
		fprintf(stderr, "Cannot initialize sigfd: %s\n", strerror(errno));
	}

	if (sigprocmask(SIG_SETMASK, &sigset, NULL) < 0) {
		fprintf(stderr, "Cannot set sigprocmask: %s\n", strerror(errno));
	}

	if (pipe(p) < 0) {
		fprintf(stderr, "Unable to create pipe: %s\n", strerror(errno));
		goto fail;
	}
	if (pipe(e) < 0) {
		fprintf(stderr, "Unable to create pipe: %s\n", strerror(errno));
	}

   rc = ndmp_dispatcher_add_fd(sess, p[0], NDMP_IN, ndmp_data_read_data);
   rc += ndmp_dispatcher_add_fd(sess, e[0], NDMP_IN, ndmp_data_read_dataerr);
   rc += ndmp_dispatcher_add_fd(sess, sig, NDMP_IN, ndmp_data_read_signal);
   if (rc != 3) {
      fprintf(stderr, "Cannot add fds to dispatcher\n");
      goto fail;
   }

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Could not fork process: %s\n", strerror(errno));
		goto fail;
	}
	else if (pid > 0) {
		sess->signalfd = sig;
		sess->dumper_pid = pid;	
		sess->epipe = e[0];
		sess->pipe = p[0];
		close(p[1]);
		close(e[1]);
		return true;
	}
	
	close(p[0]);
	close(e[0]);
	close(sig);
	close(sess->backup_fd);
	/* Make args */

	close(sess->fd);
	/* Redirect stdout into pipe */
	if (dup2(p[1], 1) < 0) {
		fprintf(stderr, "Cannot run dup2 on stdout: %s\n", strerror(errno));
		exit(22);
	}
	/* stderr to pipe */
	if (dup2(e[1], 2) < 0) {
		fprintf(stderr, "Cannot run dup2 on stderr: %s\n", strerror(errno));
		exit(23);
	}

	/* Create args */
   if (!create_args_array(env, envlen, &args)) {
      exit(21);
   }

	/* Running dump */
	if (execv("/sbin/dump", args) < 0) {
		fprintf(stderr, "Cannot run dump command: %s\n", strerror(errno));
		exit(24);
	}
	exit(0);

fail:
	close(sig);
	close(p[0]);
	close(p[1]);
	close(e[0]);
	close(e[1]);
	return false;
}

bool ndmp_recv_data_connect_request(
		ndmp_session *sess)
{
	struct ndmp_data_connect_request connector;
	memset(&connector, 0, sizeof(connector));
	struct sockaddr_in addr;
	int i;

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = 0;

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_connect_request(&sess->xdrs, &connector)) {
      goto fail;
   }
   xdrrec_skiprecord(&sess->xdrs);

   if (sess->state.data_state != NDMP_DATA_STATE_IDLE) {
      ndmp_send_data_connect_reply(sess, NDMP_ILLEGAL_STATE_ERR);
      goto fail;
   }

	sess->backup_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sess->backup_fd < 0) {
		fprintf(stderr, "Error allocating socket: %s\n", strerror(errno));
		goto fail;
	}

	/* Get the tcp address from the packet */
	if (connector.addr.addr_type != NDMP_ADDR_TCP) {
		ndmp_send_data_connect_reply(sess, NDMP_ILLEGAL_ARGS_ERR);
		goto fail;
	}
	/* Skip env, no mention of what they do is provided */

	/* Connect */
	for (i=0; i < connector.addr.ndmp_addr_u.tcp_addr.tcp_addr_len; i++) {
		addr.sin_addr.s_addr = ntohl(connector.addr.ndmp_addr_u.tcp_addr.tcp_addr_val[i].ip_addr);
		addr.sin_port = ntohs(connector.addr.ndmp_addr_u.tcp_addr.tcp_addr_val[i].port);

		if (connect(sess->backup_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			continue;
		}
		else {
			sess->state.data_state = NDMP_DATA_STATE_CONNECTED;
			sess->state.addr.ip = connector.addr.ndmp_addr_u.tcp_addr.tcp_addr_val[i].ip_addr;
			sess->state.addr.port = connector.addr.ndmp_addr_u.tcp_addr.tcp_addr_val[i].port;
			break;
		}
	}

	/* Check if we connected */
	if (sess->state.data_state != NDMP_DATA_STATE_CONNECTED) {
		ndmp_send_data_connect_reply(sess, NDMP_CONNECT_ERR);
		goto fail;
	}

   if (!ndmp_send_data_connect_reply(sess, NDMP_NO_ERR))
      goto fail;

   xdr_free((xdrproc_t)xdr_ndmp_data_connect_request, &connector);
   return true;

fail:
	if (sess->backup_fd > -1) {
		close(sess->backup_fd);
		sess->backup_fd = -1;
	}
	sess->state.data_state = NDMP_DATA_STATE_IDLE;
	xdrrec_skiprecord(&sess->xdrs);	
	xdr_free((xdrproc_t)xdr_ndmp_data_connect_request, &connector);
	return false;
}


static bool ndmp_send_data_connect_reply(
		ndmp_session *sess,
		ndmp_error error)
{
	struct ndmp_data_connect_reply reply;
	memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_DATA_CONNECT))
      goto fail;

   sess->xdrs.x_op = XDR_ENCODE;
   reply.error = error;
   if (!xdr_ndmp_data_connect_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, &reply);
   return false;	
}


bool ndmp_recv_data_start_backup_request(ndmp_session *sess)
{
   struct ndmp_data_start_backup_request backup;
	memset(&backup, 0, sizeof(backup));
	int i;

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_start_backup_request(&sess->xdrs, &backup)) 
      goto fail;
   
	if (strncmp(backup.butype_name, "dump", 4) != 0) {
		ndmp_send_data_start_backup_reply(sess, NDMP_ILLEGAL_ARGS_ERR);
		goto fail;
	}

	if (sess->state.data_state != NDMP_DATA_STATE_CONNECTED) {
		ndmp_send_data_start_backup_reply(sess, NDMP_ILLEGAL_STATE_ERR);
		goto fail;
	}

   if (!spawn_dump(sess, backup.env.env_val, backup.env.env_len)) 
      goto fail;
	sess->state.data_state = NDMP_DATA_STATE_ACTIVE;
	sess->state.operation = NDMP_DATA_OP_BACKUP;

	sess->state.peer_env_len = backup.env.env_len;
	sess->state.peer_env = calloc(backup.env.env_len, sizeof(*sess->state.peer_env));
	for (i=0; i < backup.env.env_len; i++) {
		strncpy(sess->state.peer_env[i].name, backup.env.env_val[i].name, 256);
		strncpy(sess->state.peer_env[i].value, backup.env.env_val[i].value, 256);
	}

	if (!ndmp_send_data_start_backup_reply(sess, NDMP_NO_ERR)) 
		goto fail;

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_start_backup_request, &backup);
	return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_start_backup_request, &backup);
   return false;
}


bool ndmp_send_data_start_backup_reply(
      ndmp_session *sess,
      ndmp_error error)
{
   struct ndmp_data_start_backup_reply reply;
	memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_DATA_START_BACKUP))
      goto fail;

   sess->xdrs.x_op = XDR_ENCODE;
   reply.error = error;
   if (!xdr_ndmp_data_start_backup_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) 
      goto fail;
   xdr_free((xdrproc_t)xdr_ndmp_data_start_backup_reply, &reply);
   return true;
fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_start_backup_reply, &reply);
   return false;
}


static bool ndmp_data_read_data(
		ndmp_session *sess)
{
	int rrc, wrc;
	char data[1024];
	rrc = read(sess->pipe, data, 1024);
	if (rrc < 0) {
		fprintf(stderr, "Unable to read dump data: %s\n", strerror(errno));
		ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_INTERNAL_ERROR);
		goto fin;
	}
	if (rrc == 0) {
		goto fin;
	}
	wrc = write(sess->backup_fd, data, rrc);
	if (wrc < 0) {
		ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_CONNECT_ERROR);
		fprintf(stderr, "Cannot write to backup fd socket: %s\n", strerror(errno));
		goto fin;
	}
	/* TODO: Make est time remaining work */
	sess->state.bytes_processed += wrc;
	if (sess->state.bytes_processed > 0) {
		sess->state.bytes_remaining -= wrc;
		if (sess->state.bytes_remaining < 0)
			sess->state.bytes_remaining = 0;
	}
	return true;

fin:
	return false;
}

static bool ndmp_data_read_dataerr(
      ndmp_session *sess)
{
   int rrc, wrc;
	char data[8192];
   rrc = read(sess->epipe, data, 8191);
   if (rrc < 0) {
      fprintf(stderr, "Unable to read dump error data: %s\n", strerror(errno));
		ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_INTERNAL_ERROR);
      goto fin;
   }
   if (rrc == 0) {
      goto fin;
   }
	data[rrc] = 0;
	if ((strncmp(data, "  DUMP: ", 8192) == 0)) {
		return true;
	}
	if (!ndmp_send_log_message_post(sess, NDMP_LOG_NORMAL, data))
		goto fin;
   return true;

fin:
   return false;
}



static bool ndmp_data_read_signal(
		ndmp_session *sess)
{
	struct signalfd_siginfo sinfo;
	int bleft=0;

	/* We can receive the signal before the pipe has been properly emptied,
	 * therefore we must check if the pipes still have data in their buffers */

	if (ioctl(sess->pipe, FIONREAD, &bleft) < 0) {
		fprintf(stderr, "Cannot get ioctl to work: %s\n", strerror(errno));
		return false;
	}

	if (bleft > 0) {
		return true;
	}

	if (ioctl(sess->epipe, FIONREAD, &bleft) < 0) {
		fprintf(stderr, "Cannot get ioctl to work: %s\n", strerror(errno));
		return false;
	}

	if (bleft > 0) {
		return true;
	}

	/* Signal is received, and the pipe is empty, now send our notification */

	if (read(sess->signalfd, &sinfo, sizeof(sinfo)) != sizeof(sinfo)) {
		fprintf(stderr, "Error reading sig info structure\n");
		return false;
	}

	if (sinfo.ssi_signo == SIGCHLD) {
		if (sinfo.ssi_code != CLD_EXITED) {
			ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_INTERNAL_ERROR);
		}
		else if (sinfo.ssi_status != 0) {
			ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_INTERNAL_ERROR);
		}
		else {
			ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_SUCCESSFUL);
			/* do nothing.. atm */
		}
	}
	else if (sinfo.ssi_signo == SIGPIPE) {
		ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_CONNECT_ERROR);
	}
}


bool ndmp_send_notify_data_halted_post(
      ndmp_session *sess,
      ndmp_data_halt_reason why)
{
   ndmp_notify_data_halted_post halt;
   memset(&halt, 0, sizeof(halt));

   if(!ndmp_header_send(sess, NDMP_NOTIFY_DATA_HALTED))
      goto fail;

	sess->state.data_state = NDMP_DATA_STATE_HALTED;
	sess->state.halt_reason = why;
	sess->state.time_remaining = 0;
	sess->state.bytes_remaining = 0;
   sess->xdrs.x_op = XDR_ENCODE;
   halt.reason = why;

   if (!xdr_ndmp_notify_data_halted_post(&sess->xdrs, &halt)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_notify_data_halted_post, &halt);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_notify_data_halted_post, &halt);
   return false;
}


bool ndmp_recv_data_get_state_request(
		ndmp_session *sess)
{
	xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_data_get_state_reply(sess))
      goto fail;

   return true;

fail:
   return false;	
}


static bool ndmp_send_data_get_state_reply(
		ndmp_session *sess)
{
   ndmp_data_get_state_reply reply;
   memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_DATA_GET_STATE))
      goto fail;

   reply.error = NDMP_NO_ERR;
	reply.unsupported = NDMP_DATA_STATE_EST_TIME_REMAIN_UNS|NDMP_DATA_STATE_EST_BYTES_REMAIN_UNS;
	reply.operation = sess->state.operation;
	reply.state = sess->state.data_state;
	reply.halt_reason = sess->state.halt_reason;
	U64_TO_QUAD(reply.bytes_processed, sess->state.bytes_processed);
	U64_TO_QUAD(reply.est_bytes_remain, sess->state.bytes_remaining);
	reply.est_time_remain = sess->state.time_remaining;
	U64_TO_QUAD(reply.read_offset, sess->state.read_offset);
	U64_TO_QUAD(reply.read_length, sess->state.read_length);

	reply.data_connection_addr.addr_type = NDMP_ADDR_TCP;	
	reply.data_connection_addr.ndmp_addr_u.tcp_addr.tcp_addr_len = 1;
	reply.data_connection_addr.ndmp_addr_u.tcp_addr.tcp_addr_val = calloc(1, sizeof(ndmp_tcp_addr));
	reply.data_connection_addr.ndmp_addr_u.tcp_addr.tcp_addr_val[0].ip_addr = sess->state.addr.ip;
	reply.data_connection_addr.ndmp_addr_u.tcp_addr.tcp_addr_val[0].port = sess->state.addr.port;
	reply.data_connection_addr.ndmp_addr_u.tcp_addr.tcp_addr_val[0].addr_env.addr_env_len = 0;

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_data_get_state_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_data_get_state_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_get_state_reply, &reply);
   return false;	
}


bool ndmp_recv_data_get_env_request(
		ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

   if (!ndmp_send_data_get_env_reply(sess))
      goto fail;

   return true;

fail:
   return false;	
}


static bool ndmp_send_data_get_env_reply(
		ndmp_session *sess)
{
	int i;
   ndmp_data_get_env_reply reply;
   memset(&reply, 0, sizeof(reply));

   if(!ndmp_header_send_reply(sess, NDMP_DATA_GET_ENV))
      goto fail;

	if (sess->state.data_state != NDMP_DATA_STATE_ACTIVE &&
		sess->state.data_state != NDMP_DATA_STATE_HALTED) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		reply.env.env_len = 0;
		reply.env.env_val = NULL;
	}
	else {
		reply.error = NDMP_NO_ERR;
		reply.env.env_len = sess->state.peer_env_len;
		reply.env.env_val = calloc(sess->state.peer_env_len, sizeof(*reply.env.env_val));
		for (i=0; i < reply.env.env_len; i++) {
			reply.env.env_val[i].name = strdup(sess->state.peer_env[i].name);
			reply.env.env_val[i].value = strdup(sess->state.peer_env[i].value);
		}
	}

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_data_get_env_reply(&sess->xdrs, &reply)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_data_get_env_reply, &reply);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_get_env_reply, &reply);
   return false;
}


bool ndmp_recv_data_abort_request(
		ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

	if (sess->state.data_state == NDMP_DATA_STATE_IDLE) 
		if (!ndmp_send_data_abort_reply(sess, NDMP_ILLEGAL_STATE_ERR))
			goto fail;
	
	abort_dump(sess);	

   if (!ndmp_send_data_abort_reply(sess, NDMP_NO_ERR))
      goto fail;

	if (!ndmp_send_notify_data_halted_post(sess, NDMP_DATA_HALT_ABORTED))
		goto fail;

   return true;

fail:
   return false;
}


static bool ndmp_send_data_abort_reply(
		ndmp_session *sess,
		ndmp_error error)
{
   ndmp_data_abort_reply abort;
   memset(&abort, 0, sizeof(abort));

   if(!ndmp_header_send_reply(sess, NDMP_DATA_ABORT))
      goto fail;

	abort.error = error;

   if (!xdr_ndmp_data_abort_reply(&sess->xdrs, &abort)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_data_abort_reply, &abort);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_abort_reply, &abort);
   return false;
}


bool ndmp_recv_data_stop_request(
		ndmp_session *sess)
{
   xdrrec_skiprecord(&sess->xdrs);

   if (sess->state.data_state != NDMP_DATA_STATE_HALTED)
      if (!ndmp_send_data_stop_reply(sess, NDMP_ILLEGAL_STATE_ERR))
         goto fail;

   stop_dump(sess);

   if (!ndmp_send_data_stop_reply(sess, NDMP_NO_ERR))
      goto fail;

   return true;

fail:
   return false;	
}


static bool ndmp_send_data_stop_reply(
		ndmp_session *sess,
		ndmp_error error)
{
   ndmp_data_stop_reply abort;
   memset(&abort, 0, sizeof(abort));

   if(!ndmp_header_send_reply(sess, NDMP_DATA_STOP))
      goto fail;

   abort.error = error;

   if (!xdr_ndmp_data_stop_reply(&sess->xdrs, &abort)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

   xdr_free((xdrproc_t)xdr_ndmp_data_stop_reply, &abort);
   return true;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_stop_reply, &abort);
   return false;
}
