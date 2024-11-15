#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/netfilter.h> /* NF_DROP, NF_ACCEPT */

SEC("netfilter") /* hint to BPF loader that this is an netfilter BPF program */
int hw1secws(const struct bpf_nf_ctx *ctx) {
  const struct nf_hook_state *state = ctx->state;
  int routing_decision = ctx->state->hook;

  if (routing_decision == NF_INET_LOCAL_IN ||
      routing_decision == NF_INET_LOCAL_OUT)
    return NF_DROP;

  return NF_ACCEPT;
}

char LICENSE[] SEC("license") = "GPL";
