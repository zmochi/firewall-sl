## fw_sl_kern.c

XDP BPF program, to be loaded into the kernel. The netfilter documentation should be read before this.

Wrapper struct for entries in hash map, for extensibility.
```c
struct kern_pkt_dec {
  enum pkt_decision pkt_dec;
};
```

Definitions of BPF maps. BPF maps are data structures who (most of the time) are accessible from both userspace and the BPF program. [Docs](https://docs.ebpf.io/linux/concepts/maps/)

First we define a queue, for sending packets to userspace. The macros `__uint` and `__type` simply define fields in the struct (More details in the docs above)

Then a hash map is defined to store decision on each packet. The idea is that we keep a key for each incoming packet, and send this index to userspace in the queue (Along with packet info such as IP addresses and ports). Then, userspace stores its decision on the packet (pass/drop) in the hash map, using the key. In-between, the BPF program polls for an update on that key in the hash map.

```c
struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(key_size, 0); /* queue has no keys */
  __type(value, struct packet_info);
  __uint(max_entries, PREPROCESS_QUEUE_CAP);
} preprocess_pkts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, unsigned long);
  __type(value, enum pkt_decision);
  __uint(max_entries, PKT_DEC_HASH_CAP);
  /* userspace programs should only write to this map: */
  __uint(map_flags, BPF_F_WRONLY);
} pkt_decision SEC(".maps");

```

This section should be fairly self-explanatory. Still haven't decided how to determine the direction of the packet so that field is left untouched.

```c
/**
 * @brief parses a packet to a struct representing the info needed to make a
 * decision in userspace firewall.
 *
 * it is assumed the packet is IPv4 and TCP protocol
 *
 * @param data pointer to start of packet
 * @param data_end pointer to end of packet
 * @param pkt_core packet struct, to parse data into
 * @return [TODO:return]
 */
static int xdp_to_packet(void *data, void *data_end,
                         struct packet_info *pkt_core) {
  /* check bounds */
  if ((char *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct tcphdr) >
      (char *)data_end)
    return -1;

  struct iphdr *iph = (struct iphdr *)((char *)data + sizeof(struct ethhdr));

  struct tcphdr *tcp = (struct tcphdr *)((char *)iph + sizeof(struct iphdr));

  pkt_core->ip_src = bpf_ntohs(iph->saddr);
  pkt_core->ip_dst = bpf_ntohs(iph->daddr);
  /* per the documentation the packet should already be IPV4 and TCP, so just
   * set these fields */
  pkt_core->ip_p = IPPROTO_TCP;
  pkt_core->eth_p = ETH_P_IP;
  pkt_core->port_src = bpf_ntohs(tcp->source);
  pkt_core->port_dst = bpf_ntohs(tcp->dest);
  pkt_core->direction = 16; /* TODO */

  return 0;
}

/**
 * @brief returns the protocol field of the ethernet header, converted to host
 * byte order
 *
 * @param data start of ethernet packet
 * @param data_end end of ethernet packet
 * @return 16 protocol bits
 */
static uint16 lookup_eth_proto(char *data, char *data_end) {
  if (data + sizeof(struct ethhdr) > data_end)
    return 0xFFFF;

  struct ethhdr *ethhdr = (struct ethhdr *)data;

  return bpf_ntohs(ethhdr->h_proto);
}

static uint8 lookup_ipv4_proto(char *data, char *data_end) {
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return 0x00; /* reserved protocol value, can't be a real protocol */

  struct iphdr *iphdr = (struct iphdr *)(data + sizeof(struct ethhdr));

  return iphdr->protocol;
}

```

See explanations for how communication between the BPF program and userspace work above map definitions. `pkt_cnt` is the key for the hash map (Simply a counter for how many packets were sent).

`bpf_map_update/push/lookup_elem` are helper functions from `libbpf`, used to update the map data structures. `pkt_decision` and `preprocess_pkts` are the names of the BPF maps. `pkt_core` is the packet to send to userspace.

```c
unsigned long pkt_cnt = 0;

static int query_usersp_pkt_dec(struct packet_info *pkt_core,
                                unsigned long *poll_cnt) {
  long err;
  unsigned long pkt_id;
  enum pkt_decision dec = PKT_NODC;
  enum pkt_decision *map_dec;

  pkt_id = __sync_fetch_and_add(&pkt_cnt, 1);
  /* make sure decision is set to PKT_NODC before submitting to userspace */
  err = bpf_map_update_elem(&pkt_decision, &pkt_id, &dec, BPF_ANY);
  if (err < 0) {
  }

  err = bpf_map_push_elem(&preprocess_pkts, pkt_core, 0);
  if (err < 0) {
    /* unrecoverable? can't queue packet... */
    goto unrecoverable_err;
  }

  /* poll for userspace decision */
  *poll_cnt = 0;
  do {
    /* count number of poll retries in while loop */
    *poll_cnt += 1;
    /* query hashmap for decision */
    map_dec = bpf_map_lookup_elem(&pkt_decision, &pkt_id);

    if (map_dec == NULL) {
      /* unrecoverable, no entry was found (but entry was inserted on
       * bpf_map_update_elem()), since entry was not found, no need to delete it
       * either */
      goto unrecoverable_err;
    }

    /* poll_cnt must be limited otherwise program can't pass verifier
     * (possibility of infinite loop) */
  } while (*map_dec == PKT_NODC || *poll_cnt < MAX_POLL);

  /* delete packet ID from hashmap after decision was made */
  err = bpf_map_delete_elem(&pkt_decision, &pkt_id);
  if (err < 0) {
    /* unrecoverable, couldn't delete element that was looked up with no error
     */
    goto unrecoverable_err;
  }

  if (*map_dec != PKT_PASS || *map_dec != PKT_DROP) {
    /* unrecoverable, either userspace wrote bad value, or the hashmap entry
     * changed after while loop exited */
    goto unrecoverable_err;
  }
  return *map_dec; /* either PKT_DROP or PKT_PASS */

unrecoverable_err:
  return PKT_ERR;
}

```

Fairly self explanatory?

```c
SEC("xdp")
int firewall_stateless(struct xdp_md *ctx) {
  /* a count of how many times we polled userspace for an answer for the packet,
   * for profiling. passed to query_usersp_pkt_dec() */
  unsigned long poll_cnt = 0;
  struct packet_info pkt_core;
  enum pkt_decision dec = PKT_NODC;

  char *data = (char *)(long)ctx->data;
  char *data_end = (char *)(long)ctx->data_end;

  /* only enforce rules on IPv4 and TCP protocol */
  uint16 eth_proto = lookup_eth_proto(data, data_end);
  if (eth_proto == 0xFFFF) // malformed packet
    return XDP_DROP;
  else if (eth_proto != ETH_P_IP)
    return XDP_PASS;

  /* same as above */
  uint8 ip_proto = lookup_ipv4_proto(data, data_end);
  if (ip_proto == 0x00) // malformed packet
    return XDP_DROP;
  else if (ip_proto != IPPROTO_TCP)
    return XDP_PASS;

  /* fill firewall relevant information from packet into pkt_core */
  xdp_to_packet(data, data_end, &pkt_core);

  dec = query_usersp_pkt_dec(&pkt_core, &poll_cnt);

  switch (dec) {
  case PKT_ERR:
    /* drop packet on error */
    /* TODO add some kind of log here to indicate err */
    [[fallthrough]];
  case PKT_DROP:
    return XDP_DROP;
  case PKT_PASS:
    return XDP_PASS;

  default:
    /* TODO add err log here */
    return XDP_ABORTED; /* report serious error */
  }
}
```

## fw_sl_user.c

Very similar to the netfilter userspace program - load the program and attach to kernel (The `SEC("xdp")` in `fw_sl_kern.c` lets the loader know this should be attached to XDP hook).

`bpf_map__lookup_elem` and similar helper functions are the userspace versions (double underscore) used to access maps from userspace. Behind the scenes this is a syscall called `bpf()` - more info in the [Docs](https://docs.ebpf.io/linux/)

## Makefile
Basically the same as the one in the netfilter BPF program.

## fw_sl.h

Shared definitions between the BPF program and the userspace program.
