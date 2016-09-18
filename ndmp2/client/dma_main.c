#include "common.h"
#include "ndmp_common.h"

int main() 
{
	ndmp_session *sess = NULL;
	sess = ndmp_connect("192.168.122.53", NDMPSRV_PORT, "matthew", "abc123");
	if (!sess)
		goto fail;
	int i,j;
	uint32_t attrs;

/* Not supported by ref implementation */
	if (!ndmp_send_config_get_butype_info_request(sess))
		goto fail;

	if (!ndmp_recv_config_get_butype_info_reply(sess))
		goto fail;

	if (!ndmp_send_config_get_connection_type_request(sess))
		goto fail;
	if (!ndmp_recv_config_get_connection_type_reply(sess))
		goto fail;

	if (!ndmp_send_config_get_fs_info_request(sess))
		goto fail;
	if (!ndmp_recv_config_get_fs_info_reply(sess))
		goto fail;

   printf("BACKUP TYPES: %d\n", sess->bklist_len);
   for (i=0; i < sess->bklist_len; i++) {
      printf("Backup Type Name: %s\n", sess->bklist[i].backup_type);
      printf("Variables:\n");
      for (j=0; j < sess->bklist[i].metadata_len; j++) {
         printf("\t%s: %s\n", sess->bklist[i].metadata[j].name, sess->bklist[i].metadata[j].value);
      }
      printf("Backup Attributes: (%d)\n", sess->bklist[i].attrs);
      attrs = sess->bklist[i].attrs;
      if (attrs & NDMP_BUTYPE_BACKUP_FILELIST)
         printf("\tThe backup tpye supports archiving of selective files as specified by the file list\n");
      if (attrs & NDMP_BUTYPE_RECOVER_FILELIST)
         printf("\tThe backup type suppots recovery of individual files\n");
      if (attrs & NDMP_BUTYPE_BACKUP_DIRECT)
         printf("\tThe backup type genrates valid file info data usable for direct access recovery\n");
      if (attrs & NDMP_BUTYPE_RECOVER_DIRECT)
         printf("\tThe backup type supports direct access recovery (positioning of offset within image and recovery of the specified file\n");
      if (attrs & NDMP_BUTYPE_BACKUP_INCREMENTAL)
         printf("\tThe backup type supports a incremental backup\n");
      if (attrs & NDMP_BUTYPE_RECOVER_INCREMENTAL)
         printf("\tThe backup type supports incremental-only recovery\n");
      if (attrs & NDMP_BUTYPE_BACKUP_UTF8)
         printf("\tThe backup type supports UTF8 format in the file history\n");
      if (attrs & NDMP_BUTYPE_RECOVER_UTF8)
         printf("\tThe backup type supports UFT8 format in the recovered file list\n");
      if (attrs & NDMP_BUTYPE_BACKUP_FH_FILE)
         printf("\tThe backup type supports a generation of file history using NDMP_FH_ADD_FILE requests\n");
      if (attrs & NDMP_BUTYPE_BACKUP_FH_DIR)
         printf("\tThe backup type supports the generation of file history using NDMP_FH_ADD_DIR and NDMP_FH_ADD_NODE requests\n");
      if (attrs & NDMP_BUTYPE_RECOVER_FILEHIST)
         printf("\tThe backup type supports NDMP_DATA_START_RECOVERY_FILEHIST operations which recovers file history from the backup data\n");
      if (attrs & NDMP_BUTYPE_RECOVER_FH_FILE)
         printf("\tThe backup type supports the generation of file format file history for recovery of file history\n");
      if (attrs & NDMP_BUTYPE_RECOVER_FH_DIR)
         printf("\tThe backup type supports the generation of node/dir format file history for recovery of file history\n");
      if (!attrs)
         printf("\tNo features are supported.\n");
      printf("\n");
   }

	printf("FILESYSTEMS: %d\n\n", sess->fslist_len);
	for (i=0; i < sess->fslist_len; i++) {
		printf("FS Physical Name: %s\n", sess->fslist[i].fs_physical_device);
		printf("FS Logical Name: %s\n", sess->fslist[i].fs_logical_device);
		printf("FS Type: %s\n", sess->fslist[i].fs_type);
		printf("FS Avail Size: %llu\n", sess->fslist[i].avail_size);
		printf("FS Total Size: %llu\n", sess->fslist[i].total_size);
		printf("FS Used Size: %llu\n", sess->fslist[i].used_size);
		printf("FS Total Inodes: %llu\n", sess->fslist[i].total_inodes);
		printf("FS Used Inodes: %llu\n", sess->fslist[i].used_inodes);
		printf("FS Environment variables:\n");
		for (j=0; j < sess->fslist[i].metadata_len; j++) {
			printf("\t%s: %s\n", sess->fslist[i].metadata[j].name, sess->fslist[i].metadata[j].value);
		}
		printf("\n");
	}

	printf("Fetching state..\n");
	if (!ndmp_send_data_get_state_request(sess))
		goto fail;
	if (!ndmp_recv_data_get_state_reply(sess))
		goto fail;

	printf("Starting backup..\n");
	if (!ndmp_send_data_connect_request(sess))
		goto fail;
	if (!ndmp_recv_data_connect_reply(sess))
		goto fail;

	if (!ndmp_send_data_start_backup_request(sess, "dump", sess->bklist[0].metadata, sess->bklist_len))
		goto fail;
	if (!ndmp_recv_data_start_backup_reply(sess))
		goto fail;


/* Abort
	if (!ndmp_send_data_abort_request(sess))
		goto fail;
	if (!ndmp_recv_data_abort_reply(sess))
		goto fail;
*/

/* Stop 
	printf("Sending stop..\n");
	if (!ndmp_send_data_stop_request(sess))
		goto fail;
	if (!ndmp_recv_data_stop_reply(sess))
		goto fail;
*/
	printf("Doing dispatcher..\n");
	if (!ndmp_dma_dispatcher(sess)) {
		printf("failed\n");
		goto fail;
	}

//   printf("Got %d bytes of backup data\n", sess->backup->bytes_received);
	printf("Our state: %d\n", sess->backup->data_state);

   printf("Fetching state..\n");
   if (!ndmp_send_data_get_state_request(sess)) {
      goto fail;
	}
   if (!ndmp_recv_data_get_state_reply(sess)) {
      goto fail;
	}

	if (!ndmp_send_data_get_env_request(sess))
		goto fail;
	if (!ndmp_recv_data_get_env_reply(sess)) 
		goto fail;

	printf("FINAL ENVS\n");
	for (i=0; i < sess->peer_env_len; i++) {
		printf("\t%s: %s\n", sess->peer_env[i].name, sess->peer_env[i].value);
	}

	if (!ndmp_send_data_stop_request(sess))
		goto fail;
	if (!ndmp_recv_data_stop_reply(sess))
		goto fail;

	printf("success\n");
	ndmp_disconnect(sess);
	ndmp_free_session(sess);
	return 0;

fail:
	ndmp_disconnect(sess);
	ndmp_free_session(sess);
	printf("Failed\n");
	return 1;
}
