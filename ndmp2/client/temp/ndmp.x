
enum ndmp_header_message_type  
{ 
    NDMP_MESSAGE_REQUEST          = 0, 
    NDMP_MESSAGE_REPLY            = 1 
}; 
 
const NDMP_MESSAGE_POST = NDMP_MESSAGE_REQUEST; 
 
struct ndmp_pval 
{ 
    string      name<>; 
    string      value<>; 
}; 
 
struct ndmp_u_quad 
{ 
    u_long high; 
    u_long low; 
}; 
 
 /* Note: because of extensibility, this is */ 
 /* not a complete list of errors. */ 
enum ndmp_error  
{ 
    NDMP_NO_ERR                     =  0, 
    NDMP_NOT_SUPPORTED_ERR          =  1, 
    NDMP_DEVICE_BUSY_ERR            =  2, 
    NDMP_DEVICE_OPENED_ERR          =  3, 
    NDMP_NOT_AUTHORIZED_ERR         =  4, 
    NDMP_PERMISSION_ERR             =  5, 
    NDMP_DEV_NOT_OPEN_ERR           =  6, 
    NDMP_IO_ERR                     =  7,    
    NDMP_TIMEOUT_ERR                =  8,    
    NDMP_ILLEGAL_ARGS_ERR           =  9,    
    NDMP_NO_TAPE_LOADED_ERR         = 10,    
    NDMP_WRITE_PROTECT_ERR          = 11,    
    NDMP_EOF_ERR                    = 12,    
    NDMP_EOM_ERR                    = 13,    
    NDMP_FILE_NOT_FOUND_ERR         = 14,    
    NDMP_BAD_FILE_ERR               = 15,    
    NDMP_NO_DEVICE_ERR              = 16,    
    NDMP_NO_BUS_ERR                 = 17,    
    NDMP_XDR_DECODE_ERR             = 18,    
    NDMP_ILLEGAL_STATE_ERR          = 19,    
    NDMP_UNDEFINED_ERR              = 20,    
    NDMP_XDR_ENCODE_ERR             = 21,    
    NDMP_NO_MEM_ERR                 = 22,    
    NDMP_CONNECT_ERR                = 23,  
    NDMP_SEQUENCE_NUM_ERR           = 24,    
    NDMP_READ_IN_PROGRESS_ERR       = 25, 
    NDMP_PRECONDITION_ERR           = 26,  
    NDMP_CLASS_NOT_SUPPORTED_ERR    = 27, 
    NDMP_VERSION_NOT_SUPPORTED_ERR  = 28, 
    NDMP_EXT_DUPL_CLASSES_ERR       = 29, 
    NDMP_EXT_DANDN_ILLEGAL_ERR       = 30 
}; 
 
/* Note: Because of extensibility, this */ 
/* is not a complete list of messages */ 
enum ndmp_message  
{ 
     
    NDMP_CONNECT_OPEN               = 0x900, 
    NDMP_CONNECT_CLIENT_AUTH        = 0x901, 
    NDMP_CONNECT_CLOSE              = 0x902, 
    NDMP_CONNECT_SERVER_AUTH        = 0x903, 
 
    NDMP_CONFIG_GET_HOST_INFO       = 0x100, 
    NDMP_CONFIG_GET_CONNECTION_TYPE = 0x102,           
    NDMP_CONFIG_GET_AUTH_ATTR       = 0x103, 
    NDMP_CONFIG_GET_BUTYPE_INFO     = 0x104, 
    NDMP_CONFIG_GET_FS_INFO         = 0x105, 
    NDMP_CONFIG_GET_TAPE_INFO       = 0x106, 
    NDMP_CONFIG_GET_SCSI_INFO       = 0x107, 
    NDMP_CONFIG_GET_SERVER_INFO     = 0x108, 
    NDMP_CONFIG_SET_EXT_LIST        = 0x109, 
    NDMP_CONFIG_GET_EXT_LIST        = 0x10A, 
 
    NDMP_SCSI_OPEN                  = 0x200,     
    NDMP_SCSI_CLOSE                 = 0x201, 
    NDMP_SCSI_GET_STATE             = 0x202, 
    NDMP_SCSI_RESET_DEVICE          = 0x204, 
    NDMP_SCSI_EXECUTE_CDB           = 0x206, 
 
    NDMP_TAPE_OPEN                  = 0x300, 
    NDMP_TAPE_CLOSE                 = 0x301, 
    NDMP_TAPE_GET_STATE             = 0x302, 
    NDMP_TAPE_MTIO                  = 0x303, 
    NDMP_TAPE_WRITE                 = 0x304, 
    NDMP_TAPE_READ                  = 0x305, 
    NDMP_TAPE_EXECUTE_CDB           = 0x307, 
 
    NDMP_DATA_GET_STATE             = 0x400, 
    NDMP_DATA_START_BACKUP          = 0x401, 
    NDMP_DATA_START_RECOVER         = 0x402, 
    NDMP_DATA_ABORT                 = 0x403, 
    NDMP_DATA_GET_ENV               = 0x404, 
    NDMP_DATA_STOP                  = 0x407, 
    NDMP_DATA_LISTEN                = 0x409,  
    NDMP_DATA_CONNECT               = 0x40A, 
    NDMP_DATA_START_RECOVER_FILEHIST = 0x40B, 
 
    NDMP_NOTIFY_DATA_HALTED         = 0x501,     
    NDMP_NOTIFY_CONNECTION_STATUS   = 0x502,     

    NDMP_NOTIFY_MOVER_HALTED        = 0x503, 
    NDMP_NOTIFY_MOVER_PAUSED        = 0x504, 
    NDMP_NOTIFY_DATA_READ           = 0x505, 
 
    NDMP_LOG_FILE                   = 0x602, 
    NDMP_LOG_MESSAGE                = 0x603, 
 
    NDMP_FH_ADD_FILE                = 0x703, 
    NDMP_FH_ADD_DIR                 = 0x704, 
    NDMP_FH_ADD_NODE                = 0x705, 
 
    NDMP_MOVER_GET_STATE            = 0xA00, 
    NDMP_MOVER_LISTEN               = 0xA01, 
    NDMP_MOVER_CONTINUE             = 0xA02, 
    NDMP_MOVER_ABORT                = 0xA03, 
    NDMP_MOVER_STOP                 = 0xA04, 
    NDMP_MOVER_SET_WINDOW           = 0xA05, 
    NDMP_MOVER_READ                 = 0xA06, 
    NDMP_MOVER_CLOSE                = 0xA07, 
    NDMP_MOVER_SET_RECORD_SIZE      = 0xA08, 
    NDMP_MOVER_CONNECT              = 0xA09, 
 
    NDMP_EXT_STANDARD_BASE          = 0x10000, 
 
    NDMP_EXT_PROPRIETARY_BASE       = 0x20000000 
};

enum ndmp_connection_status_reason 
{ 
	NDMP_CONNECTED  = 0, 
	NDMP_SHUTDOWN   = 1, 
	NDMP_REFUSED    = 2  
};

enum ndmp_auth_type  
{ 
	NDMP_AUTH_NONE  = 0, 
	NDMP_AUTH_TEXT  = 1, 
	NDMP_AUTH_MD5   = 2 
};

enum ndmp_addr_type  
{ 
	NDMP_ADDR_LOCAL    = 0, 
	NDMP_ADDR_TCP      = 1, 
	NDMP_ADDR_RESERVED = 2, 
	NDMP_ADDR_IPC      = 3 
};

union ndmp_auth_attr
   switch (enum ndmp_auth_type auth_type)
{
      case NDMP_AUTH_NONE:
         void;
      case NDMP_AUTH_TEXT:
         void;
      case NDMP_AUTH_MD5:
         opaque challenge[64];
};

struct ndmp_header  
{ 
    u_long                    sequence; 
    u_long                    time_stamp; 
    ndmp_header_message_type  message_type; 
    ndmp_message              message_code; 
    u_long                    reply_sequence; 
    ndmp_error                error_code; 
}; 

struct ndmp_notify_connection_status_post 
{ 
	ndmp_connection_status_reason       reason; 
	u_short                             protocol_version; 
	string                              text_reason<>; 
}; 

struct ndmp_connect_open_request  
{ 
	u_short          protocol_version; 
};

struct ndmp_connect_open_reply  
{ 
	ndmp_error       error; 
};  

struct ndmp_config_get_server_info_reply  
{ 
	ndmp_error        error; 
	string            vendor_name<>; 
	string            product_name<>; 
	string            revision_number<>; 
	ndmp_auth_type    auth_type<>; 
}; 

struct ndmp_config_get_auth_attr_request  
{ 
	ndmp_auth_type      auth_type; 
};  

struct ndmp_config_get_auth_attr_reply  
{ 
	ndmp_error          error; 
	ndmp_auth_attr      server_attr; 
}; 

struct ndmp_auth_md5  
{ 
	string   auth_id<>; 
	opaque   auth_digest[16]; 
};

struct ndmp_auth_text
{
	string	auth_id<>;
	string	auth_password<>;
};

union ndmp_auth_data
   switch (enum ndmp_auth_type   auth_type)
{
   case NDMP_AUTH_NONE:
      void;
   case NDMP_AUTH_TEXT:
      struct ndmp_auth_text   auth_text;
   case NDMP_AUTH_MD5:
      struct ndmp_auth_md5    auth_md5;
};

struct ndmp_connect_client_auth_request
{
   ndmp_auth_data       auth_data;
};

struct ndmp_connect_client_auth_reply
{
   ndmp_error           error;
};

struct ndmp_butype_info
{
   string      butype_name<>;
   ndmp_pval   default_env<>;
   u_long      attrs;
};

struct ndmp_config_get_butype_attr_reply
{
   ndmp_error            error;
   ndmp_butype_info      butype_info<>;
};

struct ndmp_config_get_connection_type_reply  
{ 
	ndmp_error          error; 
	ndmp_addr_type      addr_types<>; 
}; 

struct ndmp_fs_info  
{ 
	u_long            unsupported; 
	string            fs_type<>; 
	string            fs_logical_device<>; 
	string            fs_physical_device<>; 
	ndmp_u_quad       total_size; 
	ndmp_u_quad       used_size; 
	ndmp_u_quad       avail_size; 
	ndmp_u_quad       total_inodes; 
	ndmp_u_quad       used_inodes; 
	ndmp_pval         fs_env<>; 
	string            fs_status<>; 
}; 

struct ndmp_config_get_fs_info_reply  
{ 
	ndmp_error        error; 
	ndmp_fs_info      fs_info<>; 
}; 

struct ndmp_ipc_addr  
{ 
	opaque comm_data<>; 
};  

struct ndmp_tcp_addr  
{ 
	u_long       ip_addr; 
	u_short      port; 
	ndmp_pval    addr_env<>; 
};

union ndmp_addr  
switch (ndmp_addr_type addr_type)  
{ 
	case NDMP_ADDR_LOCAL: 
		void; 
	case NDMP_ADDR_TCP: 
		ndmp_tcp_addr  tcp_addr<>; 
	case NDMP_ADDR_IPC: 
		ndmp_ipc_addr  ipc_addr; 
};

struct ndmp_data_connect_request
{
   ndmp_addr   addr;
};

struct ndmp_data_connect_reply  
{ 
	ndmp_error  error; 
};

