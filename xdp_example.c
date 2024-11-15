#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_example(void *ctx) {
  bpf_printk("Hello World");
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
