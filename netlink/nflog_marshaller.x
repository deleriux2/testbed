const NFLOG_PROTO_ICMP = 1;
const NFLOG_PROTO_TCP = 6;
const NFLOG_PROTO_UDP = 17;

struct portspec {
  unsigned int srcport;
  unsigned int dstport;
};

struct icmpspec {
  unsigned int code;
  unsigned int type;
};

struct nflog_log_timestamp {
  int tv_sec;
  int tv_usec;
};

union protocol_data
switch (unsigned int protocol) {
  case NFLOG_PROTO_ICMP:
    icmpspec icmp;
  case NFLOG_PROTO_TCP:
    portspec tcp;
  case NFLOG_PROTO_UDP:
    portspec udp;
}; 

struct nflog_log {
  string user<128>;
  string group<128>;
  string indev<128>;
  string outdev<128>;
  string physindev<128>;
  string physoutdev<128>;
  string prefix<64>;
  string hwaddr<16>;
  string payload<>;
  nflog_log_timestamp ts; 
  int payloadlen;
  int mark;
  unsigned int pktsz;
  unsigned int ttl;
  string protocol<16>;
  string srcaddr<16>;
  string dstaddr<16>;

  protocol_data pdata;
};
