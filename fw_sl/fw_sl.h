/* this file defined userspace-kernel shared data structures */

/* capacities of preprocess and postprocess queues */
#define PREPROCESS_QUEUE_CAP 100
#define PKT_DEC_HASH_CAP 100

/* max number of times the eBPF program will poll for a userspace decision of a
 * packet */
#define MAX_POLL (1ULL << 32)

typedef unsigned char uint8;
typedef short unsigned int uint16;
typedef unsigned int uint32;

_Static_assert(sizeof(uint8) == 1, "uint8 typedef has size != 8 bits");
_Static_assert(sizeof(uint16) == 2, "uint16 typedef has size != 16 bits");
_Static_assert(sizeof(uint32) == 4, "uint32 typedef has size != 32 bits");

typedef uint16 port;
typedef uint16 eth_proto;
typedef uint8 ip_proto;
typedef uint32 ipaddr;

typedef enum {
  PROTO_TCP,
  PROTO_UDP,
  PROTO_ICMP,
} proto;

typedef enum {
  DIRCT_IN,
  DIRCT_OUT,
} direction;

struct packet_info {
  ipaddr ip_src;
  ipaddr ip_dst;
  port port_src;
  port port_dst;
  ip_proto ip_p;
  eth_proto eth_p;
  direction direction;
  int pkt_dec_map_index;
};

enum pkt_decision {
  PKT_PASS,
  PKT_DROP,
  PKT_NODC,
  PKT_ERR,
};
