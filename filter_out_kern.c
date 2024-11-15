#include "vmlinux.h"
#include <bpf/bpf_core_read.h> /* struct bpf_nf_ctx is unstable (its internals may be changed in the future). bpf_core_read() should be used to read from this struct, to keep this program portable across different kernels */

/* some kernel #define's must be manually defined in eBPF programs that use
 * `vmlinux.h` */
#define NF_DROP 0

SEC("netfilter") /* hint to BPF loader that this is an netfilter BPF program */
int filter_out(const struct bpf_nf_ctx *ctx) { return NF_DROP; }

char LICENSE[] SEC("license") = "GPL";
