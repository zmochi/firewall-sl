#include "vmlinux.h"

/* some kernel #define's must be manually defined in eBPF programs that use
 * `vmlinux.h` */
#define NF_DROP 0

SEC("netfilter") /* hint to BPF loader that this is an netfilter BPF program */
int filter_kern(const struct bpf_nf_ctx *ctx) { return NF_DROP; }

char LICENSE[] SEC("license") = "GPL";
