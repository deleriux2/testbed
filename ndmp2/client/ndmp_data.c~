#include "common.h"
#include "ndmp_common.h"
#include "ndmp.h"

#include <sched.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>

volatile sig_atomic_t signalled = false; 

static int ndmp_data_backup_begin(ndmp_session *sess);
static bool ndmp_data_setup_backup(ndmp_session *sess, char *backup_type, struct envs *env, int envlen);
static uint64_t state_get_quad(ndmp_u_quad quad);
static char * state_get_est_time(uint32_t time, uint32_t unsupported);
static char * state_get_est_bytes(ndmp_u_quad bytes, uint32_t unsupported);
static char * state_get_state(enum ndmp_data_state state);
static char *state_get_halt(enum ndmp_data_halt_reason reason);
static char * state_get_operation(enum ndmp_data_operation operation);
static char * state_get_conn_addr(ndmp_addr addr);
static void ndmp_data_abort(ndmp_session *sess);


static char * state_get_conn_addr(
		ndmp_addr addr)
{
	static char state_value[INET_ADDRSTRLEN+8];
	char tmp[INET_ADDRSTRLEN];
	struct sockaddr_in a;
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = 	htonl(addr.ndmp_addr_u.tcp_addr.tcp_addr_val[0].ip_addr);
	a.sin_port = addr.ndmp_addr_u.tcp_addr.tcp_addr_val[0].port;

	memset(tmp, 0, sizeof(tmp));
	memset(&state_value, 0, sizeof(state_value));

	if (addr.addr_type == NDMP_ADDR_TCP) {
		inet_ntop(AF_INET, &a.sin_addr.s_addr, tmp, INET_ADDRSTRLEN);
		snprintf(state_value, INET_ADDRSTRLEN+8, "%s:%d", tmp, a.sin_port);
		return state_value;
	}
	else {
		return "Locally connected Mechanism";
	}
}

static char * state_get_operation(
		enum ndmp_data_operation operation)
{
	switch (operation) {
	case NDMP_DATA_OP_NOACTION:
		return "No operation in progress";
	case NDMP_DATA_OP_BACKUP:
		return "Backup in progress";
	case NDMP_DATA_OP_RECOVER:
		return "Recovery in progress";
	case NDMP_DATA_OP_RECOVER_FILEHIST:
		return "File history recovery in progress";
	default:
		return "Unknown operation";
	}
}

static uint64_t state_get_quad(
		ndmp_u_quad quad)
{
	uint64_t num = 0;
	QUAD_TO_U64(num, quad);
	return num;
}

static char * state_get_est_time(
		uint32_t time,
		uint32_t unsupported)
{
	static char estt_value[24];
	memset(estt_value, 0, sizeof(estt_value));
	int num;

	if (unsupported & NDMP_DATA_STATE_EST_TIME_REMAIN_UNS) {
		strcpy(estt_value, "Not supported");
	}
	else {
		snprintf(estt_value, sizeof(estt_value), "%d", time);
	}
	return estt_value;
}

static char * state_get_est_bytes(
		ndmp_u_quad bytes,
		uint32_t unsupported)
{
	static char estb_value[24];
	memset(estb_value, 0, sizeof(estb_value));
	int num;

	if (unsupported & NDMP_DATA_STATE_EST_BYTES_REMAIN_UNS) {
		strncpy(estb_value, "Not supported", sizeof(estb_value));
	}
	else {
		QUAD_TO_U64(num, bytes);
		snprintf(estb_value, sizeof(estb_value), "%llu", num);
	}
	return estb_value;
}

static char * state_get_state(
		enum ndmp_data_state state)
{
	switch(state) {
	case NDMP_DATA_STATE_IDLE:
		return "Idle";
	case NDMP_DATA_STATE_LISTEN:
		return "Listening";
	case NDMP_DATA_STATE_CONNECTED:
		return "Connected";
	case NDMP_DATA_STATE_ACTIVE:
		return "Active";
	case NDMP_DATA_STATE_HALTED:
		return "Halted";
	default:
		return "Unknown";
	}
}


static char *state_get_halt(
		enum ndmp_data_halt_reason reason)
{
	switch(reason) {
   case NDMP_DATA_HALT_NA:
      return "Not halted";
   case NDMP_DATA_HALT_SUCCESSFUL:
      return "Success";
   case NDMP_DATA_HALT_ABORTED:
		return "Cancelled";
   case NDMP_DATA_HALT_INTERNAL_ERROR:
		return "Internal error on data server";
   case NDMP_DATA_HALT_CONNECT_ERROR:
		return "Connection error to mover";
   default:
      return "Unknown";
	}
}


static void wakeup(int signal) {
	signalled = true;
	return;
}


/* Read the data from the backup socket.. */
static int ndmp_data_backup_begin(
		ndmp_session *sess)
{
	ndmp_databackup *backup = sess->backup;
	int fd = backup->backup_fd;
	int clifd = -1;
	int rc;
	int left;
	char *buf = calloc(1, backup->read_block_sz);
	backup->data_state = DATA_STATE_ACTIVE;

	clifd = accept(fd, NULL, 0);
	if (clifd < 0) {
		fprintf(stderr, "cannot read client socket: %s\n", strerror(errno));
		exit(1);
	}

	uint64_t total=0;
	FILE *tmp = fopen("/tmp/dump.tmp", "w");

	while (true) {
		rc = read(clifd, buf, backup->read_block_sz);
		fwrite(buf, rc, 1, tmp);

		if (rc < 0 && errno != EINTR) {
			fprintf(stderr, "Error reading from peer %s\n", strerror(errno));
			exit(1);
		}
		else if (errno == EINTR) {
			continue;
		}
		total+=rc;

		if (!backup->ready) {
			if (ioctl(clifd, FIONREAD, &left) < 0) {
				fprintf(stderr, "ioctl error: %s", strerror(errno));
				break;
			}
			if (left == 0) 
				break;
		}
	}
	fclose(tmp);
	backup->data_state = DATA_STATE_HALTED;
	printf("Total bytes received: %llu\n", total);
	exit(0);
}

static bool ndmp_data_setup_backup(
		ndmp_session *sess,
		char *backup_type,
		struct envs *env,	
		int envlen)
{
	int i;
	/* Look for the attributes to determine operational block size */
	strncpy(sess->backup->type,backup_type, 256);
	for (i=0; i < envlen; i++) {
		if (strncmp(env[i].name, "READ_BLOCK_SIZE", 256) == 0)
			sess->backup->read_block_sz = atoi(env[i].value);
      if (strncmp(env[i].name, "WRITE_BLOCK_SIZE", 256) == 0)
			sess->backup->write_block_sz = atoi(env[i].value);
	}

	/* If not found, or invalid then set here */
   if (sess->backup->read_block_sz < NDMP_MIN_BLOCK_SZ || sess->backup->read_block_sz > NDMP_MAX_BLOCK_SZ ||
      sess->backup->write_block_sz < NDMP_MIN_BLOCK_SZ  || sess->backup->write_block_sz > NDMP_MAX_BLOCK_SZ) {
		sess->backup->read_block_sz = NDMP_DEFAULT_BLOCK_SZ;
		sess->backup->write_block_sz = NDMP_DEFAULT_BLOCK_SZ;
	}
	sess->backup->ready = true;

	return true;
}


/* Spawns child process to handle inbound data */
pid_t ndmp_data_backup_init(
		ndmp_session *sess)
{
	pid_t p = 0;
   sess->backup_pid = p;
   signal(SIGALRM, wakeup);
   signal(SIGCHLD, SIG_IGN);

	p = fork();
	if (p < 0) {
		fprintf(stderr, "Unable to spawn backup process: %s\n", strerror(errno));
		goto fail;
	}
	sess->backup_pid = p;

	if (p) {
		signal(SIGTERM, SIG_DFL);
		signal(SIGALRM, SIG_DFL);
		close(sess->backup->backup_fd);
		return true;
	}

	close(sess->fd);
	if (!signalled)
		pause();
	/* Pause until ready, only till SIGALRM returns
	 * to this position  */
	if (sess->backup->ready) {
		ndmp_data_backup_begin(sess);
	}
	printf("Finished..\n");
	exit(0);

fail:
	ndmp_data_abort(sess);
	return false;
}


void ndmp_data_disconnect(
		ndmp_session *sess)
{
	/* No action on child process */
	if (!sess->backup_pid)
		return;
	int status;
	sess->backup->ready = 0;
	sess->backup->backup_fd = -1;
   waitpid(sess->backup_pid, &status, 0);
	sess->backup_pid = 0;
}

void ndmp_data_abort(
		ndmp_session *sess)
{
	if (!sess->backup_pid)
		return;
	sess->backup->ready = 0;
	sess->backup->backup_fd = -1;
	kill(sess->backup_pid, SIGTERM);
	sess->backup_pid = -1;
}

bool ndmp_send_data_connect_request(
		ndmp_session *sess)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = 1;
	socklen_t addrlen = sizeof(addr);
	int i;
	int fd;
	bool bound = false;

	ndmp_data_connect_request *dconnect;
	if ((dconnect = malloc(sizeof(*dconnect))) == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return false;
	}
	ndmp_tcp_addr *tcp = malloc(sizeof(*tcp));
   dconnect->addr.ndmp_addr_u.tcp_addr.tcp_addr_len = 1;
   dconnect->addr.ndmp_addr_u.tcp_addr.tcp_addr_val = tcp;

	if (!ndmp_header_send(sess, NDMP_DATA_CONNECT)) {
		goto fail;
	}

	if (getsockname(sess->fd, (struct sockaddr *)&addr, &addrlen) < 0) {
		fprintf(stderr, "Cannot obtain socket address");
		goto fail;
	}

	/* Setup a databackup socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Could not create socket: %s\n", strerror(errno));
		goto fail;
	}
	i = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &i, 4) < 0) {
		fprintf(stderr, "Cannot setsockopt on data socket: %s\n", strerror(errno));
		goto fail;
	}

	for (i=NDMPBACKUP_PORT_START; i < NDMPBACKUP_PORT_END; i++) {
		addr.sin_port = htons(i);
		if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
			continue;
		}
		bound = true;
		break;
	}

	if (!bound) {
		fprintf(stderr, "Unable to find an address to bind to\n");
		goto fail;
	}

	if (listen(fd, 1) < 0) {
		fprintf(stderr, "Cannot set listen on socket: %s\n", strerror(errno));
		goto fail;
	}

	/* Create the request */
	tcp->ip_addr = htonl(addr.sin_addr.s_addr);
	tcp->port = htons(addr.sin_port);
	tcp->addr_env.addr_env_len = 0;
	tcp->addr_env.addr_env_val = NULL;
	dconnect->addr.addr_type = NDMP_ADDR_TCP;

	sess->backup->backup_fd = fd;
	sess->backup->data_state = DATA_STATE_LISTEN;
	if (!ndmp_data_backup_init(sess)) {
		goto fail;
	}

	sess->xdrs.x_op = XDR_ENCODE;
	if (!xdr_ndmp_data_connect_request(&sess->xdrs, dconnect)) {
		goto fail;
	}

	if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
		goto fail;
	}

	xdr_free((xdrproc_t)xdr_ndmp_data_connect_request, dconnect);
	return true;

fail:
	close(fd);
	sess->backup->backup_fd = -1;
	sess->backup->data_state = DATA_STATE_LISTEN;
	sess->backup->ready = 0;
	xdr_free((xdrproc_t)xdr_ndmp_data_connect_request, dconnect);
	return false;
}


bool ndmp_recv_data_connect_reply(
		ndmp_session *sess)
{
	ndmp_header hdr;
	ndmp_data_connect_reply *dreply;
	ON_ERR("Memory allocation error", dreply = malloc(sizeof(*dreply)));
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
	if (hdr.message_code != NDMP_DATA_CONNECT) {
		fprintf(stderr, "Unexpected message code\n");
		goto fail;
	}

	if (sess->seqno != hdr.reply_sequence) {
		fprintf(stderr, "Unexpected reply sequence number\n");
		goto fail;
	}

	sess->xdrs.x_op = XDR_DECODE;
	if (!xdr_ndmp_data_connect_reply(&sess->xdrs, dreply)) {
		fprintf(stderr, "Could not decode response from server\n");
		goto fail;
	}

	if (dreply->error != NDMP_NO_ERR) {
		fprintf(stderr, "Error getting server to connect to our backup host: %s\n", ndmp_print_error(dreply->error));
		goto fail;
	}

	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, dreply);
	return true;

fail:
	xdrrec_skiprecord(&sess->xdrs);
	xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, dreply);
	return false;
}


bool ndmp_send_data_start_backup_request(
		ndmp_session *sess,
		char *backup_type,
		struct envs *envs,
		int envlen)
{
	int i,j;
	bool gotenv = false;
	ndmp_data_start_backup_request *breq = NULL;
   if ((breq = malloc(sizeof(*breq))) == NULL) {
      fprintf(stderr, "Memory allocation error\n");
      return false;
   }

	breq->butype_name = strdup(backup_type);
	breq->env.env_len = envlen;
	breq->env.env_val = calloc(sizeof(*breq->env.env_val), envlen);
	for (i=0; i < envlen; i++) {
		gotenv = false;
		for (j=0; j < sess->bklist_len; j++) {
			if (strcmp(envs[i].name, sess->bklist[j].metadata[j].name) == 0) {
				gotenv = true;
				breq->env.env_val[i].name = strdup(envs[i].name);
				breq->env.env_val[i].value = strdup(envs[i].value);
				break;
			}
		}
		if (!gotenv) {
			goto fail;
		}
	}

	ndmp_data_setup_backup(sess, backup_type, envs, envlen);
	/* Wakeup helper process, we're ready now */
	if (kill(sess->backup_pid, SIGALRM) < 0) {
		fprintf(stderr, "Cannot set backup process to resume: %s\n", strerror(errno));
		goto fail;
	}

   if (!ndmp_header_send(sess, NDMP_DATA_START_BACKUP)) {
      goto fail;
   }

   sess->xdrs.x_op = XDR_ENCODE;
   if (!xdr_ndmp_data_start_backup_request(&sess->xdrs, breq)) {
      goto fail;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      goto fail;
   }

	xdr_free((xdrproc_t )xdr_ndmp_data_start_backup_request, breq);
	return true;
fail:
   xdr_free((xdrproc_t)xdr_ndmp_data_start_backup_request, breq);
	return false;
}


bool ndmp_recv_data_start_backup_reply(
		ndmp_session *sess)
{
   ndmp_header hdr;
   ndmp_data_start_backup_reply *reply;
   ON_ERR("Memory allocation error", reply = malloc(sizeof(*reply)));
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
   if (hdr.message_code != NDMP_DATA_START_BACKUP) {
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_start_backup_reply(&sess->xdrs, reply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

   if (reply->error != NDMP_NO_ERR) {
      fprintf(stderr, "Error getting server to connect to our backup host: %s\n", ndmp_print_error(reply->error));
      goto fail;
   }

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_connect_reply, reply);
   return false;
}


bool ndmp_recv_notify_data_halted_post(
		ndmp_session *sess)
{
   ndmp_notify_data_halted_post halt;
   memset(&halt, 0, sizeof(halt));

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_notify_data_halted_post(&sess->xdrs, &halt)) {
      goto fail;	
   }

	/* Shut down data connection */
	ndmp_data_abort(sess);

	printf("Backup finished, status: ");
	switch (halt.reason) {
	case NDMP_DATA_HALT_SUCCESSFUL:
	printf("Success\n");
	break;
	case NDMP_DATA_HALT_CONNECT_ERROR:
	printf("Connection error to backup host\n");
	break;
	case NDMP_DATA_HALT_ABORTED:
	printf("Backup aborted by DMA request\n");
	break;
	case NDMP_DATA_HALT_INTERNAL_ERROR:
	printf("Peer had internal error performing backup\n");
	break;
	default:
		printf("Unknown\n");
	break;
	}

   xdr_free((xdrproc_t)xdr_ndmp_notify_data_halted_post, &halt);
   xdrrec_skiprecord(&sess->xdrs);
   return false;

fail:
   xdr_free((xdrproc_t)xdr_ndmp_notify_data_halted_post, &halt);
   xdrrec_skiprecord(&sess->xdrs);
   return false;
}


bool ndmp_send_data_get_state_request(
		ndmp_session *sess)
{
   if (!ndmp_header_send(sess, NDMP_DATA_GET_STATE)) {
      return false;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      return 0;
   }
   return true;
}


bool ndmp_recv_data_get_state_reply(
		ndmp_session *sess)
{
   ndmp_header hdr;
   ndmp_data_get_state_reply reply;
	memset(&reply, 0, sizeof(reply));
	int rc;

   if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
      fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
      return false;
   }

   if (hdr.message_type != NDMP_MESSAGE_REPLY) {
      fprintf(stderr, "Expected a message request but got something else\n");
   }
   if (hdr.message_code != NDMP_DATA_GET_STATE) {
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_get_state_reply(&sess->xdrs, &reply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

   if (reply.error != NDMP_NO_ERR) {
      fprintf(stderr, "The server data state packet returned an error: %s\n", ndmp_print_error(reply.error));
      goto fail;
   }

	/* This is probably something to remove */
   printf("CURRENT STATE\n"
         "Operation in Progress: %s\n"
         "State of Data Server: %s\n"
         "Halt State of Data Server: %s\n"
         "Bytes Processed: %llu\n"
         "Mover Connection Address: %s\n"
         "Recovery Read Offset: %llu\n"
         "Recovery Read Length: %llu\n"
         "Estimated Bytes: %s\n"
         "Estimated Time Remaining: %s\n",
      state_get_operation(reply.operation),
      state_get_state(reply.state),
      state_get_halt(reply.halt_reason),
      state_get_quad(reply.bytes_processed),
      state_get_conn_addr(reply.data_connection_addr),
      state_get_quad(reply.read_offset),
      state_get_quad(reply.read_length),
      state_get_est_bytes(reply.est_bytes_remain, reply.unsupported),
      state_get_est_time(reply.est_time_remain, reply.unsupported));
	

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_get_state_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_get_state_reply, &reply);
   return false;
}

bool ndmp_send_data_get_env_request(
		ndmp_session *sess)
{
   if (!ndmp_header_send(sess, NDMP_DATA_GET_ENV)) {
      return false;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      return true;
   }
   return 1;	
}


bool ndmp_recv_data_get_env_reply(
		ndmp_session *sess)
{
   ndmp_header hdr;
   ndmp_data_get_env_reply reply;
	memset(&reply, 0, sizeof(reply));
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
   if (hdr.message_code != NDMP_DATA_GET_ENV) {
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_get_env_reply(&sess->xdrs, &reply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

   if (reply.error != NDMP_NO_ERR) {
      fprintf(stderr, "Error getting server to provide us the environment: %s\n", ndmp_print_error(reply.error));
      goto fail;
   }

	sess->peer_env_len = reply.env.env_len;
	sess->peer_env = calloc(reply.env.env_len, sizeof(*sess->peer_env));
	for (i=0; i < reply.env.env_len; i++) {
		strncpy(sess->peer_env[i].name, reply.env.env_val[i].name, 256);
		strncpy(sess->peer_env[i].value, reply.env.env_val[i].value, 256);
	}

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_get_env_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_get_env_reply, &reply);
   return false;	
}


bool ndmp_send_data_abort_request(
		ndmp_session *sess)
{
   if (!ndmp_header_send(sess, NDMP_DATA_ABORT)) {
      return false;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      return true;
   }
   return 1;
}


bool ndmp_recv_data_abort_reply(
		ndmp_session *sess)
{
   ndmp_header hdr;
   ndmp_data_abort_reply reply;
   memset(&reply, 0, sizeof(reply));
   bool success = false;
   int rc;
   int i;

   if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
      fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
      return false;
   }

   if (hdr.message_type != NDMP_MESSAGE_REPLY) {
      fprintf(stderr, "Oops. Expected a message request but got something else\n");
		goto fail;
   }
   if (hdr.message_code != NDMP_DATA_ABORT) {
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_abort_reply(&sess->xdrs, &reply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

	printf("Response to abort: %s\n", ndmp_print_error(reply.error));

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_abort_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_abort_reply, &reply);
   return false;
}


bool ndmp_send_data_stop_request(
		ndmp_session *sess)
{
   if (!ndmp_header_send(sess, NDMP_DATA_STOP)) {
      return false;
   }

   if (!xdrrec_endofrecord(&sess->xdrs, 1)) {
      return true;
   }
   return 1;
}


bool ndmp_recv_data_stop_reply(
		ndmp_session *sess)
{
   ndmp_header hdr;
   ndmp_data_stop_reply reply;
   memset(&reply, 0, sizeof(reply));
	int rc;

   if ((rc = ndmp_header_recv(sess, &hdr)) != 1) {
      fprintf(stderr, "Error in receive request: %s\n", rc == 0 ? ndmp_print_error(hdr.error_code) : strerror(errno));
      return false;
   }

   if (hdr.message_type != NDMP_MESSAGE_REPLY) {
      fprintf(stderr, "Expected a message reply but got something else\n");
      goto fail;
   }
   if (hdr.message_code != NDMP_DATA_STOP) {
		printf("here: %x\n", hdr.message_code);
      fprintf(stderr, "Unexpected message code\n");
      goto fail;
   }

   if (sess->seqno != hdr.reply_sequence) {
      fprintf(stderr, "Unexpected reply sequence number\n");
      goto fail;
   }

   sess->xdrs.x_op = XDR_DECODE;
   if (!xdr_ndmp_data_stop_reply(&sess->xdrs, &reply)) {
      fprintf(stderr, "Could not decode response from server\n");
      goto fail;
   }

   printf("Response to stop: %s\n", ndmp_print_error(reply.error));

   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_stop_reply, &reply);
   return true;

fail:
   xdrrec_skiprecord(&sess->xdrs);
   xdr_free((xdrproc_t)xdr_ndmp_data_stop_reply, &reply);
   return false;
}
