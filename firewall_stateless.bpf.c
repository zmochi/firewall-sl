#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int firewall_stateless(struct xdp_md *ctx) {}
