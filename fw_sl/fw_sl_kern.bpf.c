#include "vmlinux.h"

#include <bpf/bpf_endian.h> /* bpf_ntohs(), bpf_htons()... */
#include <bpf/bpf_helpers.h>

#include "fw_sl.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(key_size, 0); /* queue has no keys */
  __uint(value_size, sizeof(struct packet_info));
  __type(value, struct packet_info);
  __uint(max_entries, PREPROCESS_QUEUE_CAP);
} preprocess_pkts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, 4); /* key size must be 4 according to docs.ebpf.io @
                          BPF_MAP_TYPE_PERCPU_ARRAY */
  __uint(value_size, 4);
  __uint(max_entries, 1);
} pkt_decision SEC(".maps");

/**
 * @brief parses a packet to a struct representing the info needed to make a
 * decision in userspace firewall.
 *
 * it is assumed the packet is IPv4
 *
 * @param data pointer to start of packet
 * @param data_end pointer to end of packet
 * @param pkt_core packet struct, to parse data into
 * @return [TODO:return]
 */
int xdp_to_packet_ipv4(void *data, void *data_end, uint16 eth_proto,
                       struct packet_info *pkt_core) {
  /* check bounds */
  if ((char *)data + sizeof(struct ethhdr) + sizeof(struct iphdr) >
      (char *)data_end)
    return -1;

  struct iphdr *iph = (struct iphdr *)((char *)data + sizeof(struct ethhdr));

  struct tcphdr *tcp = (struct tcphdr *)((char *)iph + sizeof(struct iphdr));

  pkt_core->ip_src = iph->saddr;
  pkt_core->ip_dst = iph->daddr;
  /* per the documentation the packet should already be IPV4 and TCP, so just
   * set these fields */
  pkt_core->ip_p = iph->protocol;
  pkt_core->eth_p = ETH_P_IP;
  pkt_core->port_src = tcp->source;
  pkt_core->port_dst = tcp->dest;
  pkt_core->direction = 16; /* TODO */

  return 0;
}

/**
 * @brief parses a packet to a struct representing the info needed to make a
 * decision in userspace firewall.
 *
 * it is assumed the packet is IPv6
 *
 * @param data pointer to start of packet
 * @param data_end pointer to end of packet
 * @param pkt_core packet struct, to parse data into
 * @return [TODO:return]
 */
int xdp_to_packet_ipv6(void *data, void *data_end,
                       struct packet_info *pkt_core) {
  /* check bounds */
  if ((char *)data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) >
      (char *)data_end)
    return -1;

  struct iphdr *iph = (struct iphdr *)((char *)data + sizeof(struct ethhdr));

  struct tcphdr *tcp = (struct tcphdr *)((char *)iph + sizeof(struct iphdr));

  pkt_core->ip_src = iph->saddr;
  pkt_core->ip_dst = iph->daddr;
  /* per the documentation the packet should already be IPV4 and TCP, so just
   * set these fields */
  pkt_core->ip_p = iph->protocol;
  pkt_core->eth_p = ETH_P_IP;
  pkt_core->port_src = tcp->source;
  pkt_core->port_dst = tcp->dest;
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
uint16 lookup_eth_proto(char *data, char *data_end) {
  if (data + sizeof(struct ethhdr) > data_end)
    return 0xFFFF;

  struct ethhdr *ethhdr = (struct ethhdr *)data;

  return bpf_ntohs(ethhdr->h_proto);
}

uint8 lookup_ipv4_proto(char *data, char *data_end) {
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return 0x00; /* reserved protocol value, can't be a real protocol */

  struct iphdr *iphdr = (struct iphdr *)(data + sizeof(struct ethhdr));

  return iphdr->protocol;
}

int query_usersp_drop_pkt(struct packet_info *pkt_core) {}

SEC("xdp")
int firewall_stateless(struct xdp_md *ctx) {
  struct packet_info pkt_core;
  void *data = (char *)(long)ctx->data;
  void *data_end = (char *)(long)ctx->data_end;

  /* only enforce rules on IPv4 and TCP protocol */
  uint16 eth_proto = lookup_eth_proto(data, data_end);
  if (eth_proto == 0xFFFF) // malformed packet
    return XDP_DROP;
  else if (eth_proto != ETH_P_IP)
    return XDP_PASS;

  uint8 ip_proto = lookup_ipv4_proto(data, data_end);
  if (ip_proto == 0x00) // malformed packet
    return XDP_DROP;
  else if (ip_proto != IPPROTO_TCP)
    return XDP_PASS;

  xdp_to_packet_ipv4(data, data_end, &pkt_core);

  if (query_usersp_drop_pkt(&pkt_core))
    return XDP_DROP;

  return XDP_PASS;
}
