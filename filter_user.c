/* see 'Learning eBPF', page 102 */
#include "filter_kern.skel.h"
#include <unistd.h> /* sleep() */

#define NFPROTO_IPV4 2
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3

int main() {
  /* filter.skel.h defines the BPF kernel program. this struct is defined in
   * filter.skel.h and is loaded with information about the BPF program in the
   * filter_bpf__open_and_load() call */
  struct filter_kern_bpf *skel;
  int err;

  /* can also use bpf_object__open_file() to directly open the bpf object file
   * must destroy this later with filter_bpf__destroy() */
  skel = filter_kern_bpf__open_and_load();
  if (skel == NULL) {
    exit(1);
  }

  struct bpf_netfilter_opts opts_in = {.pf = NFPROTO_IPV4,
                                       .hooknum = NF_INET_LOCAL_IN,
                                       .priority = 0,
                                       .sz = sizeof(struct bpf_netfilter_opts)};
  struct bpf_netfilter_opts opts_out = {.pf = NFPROTO_IPV4,
                                        .hooknum = NF_INET_LOCAL_OUT,
                                        .priority = 0,
                                        .sz =
                                            sizeof(struct bpf_netfilter_opts)};

  /* attach bpf program to kernel */
  if (bpf_program__attach_netfilter(skel->progs.filter_kern, &opts_in) ==
      NULL) {
    goto cleanup_open_load;
  };

  if (bpf_program__attach_netfilter(skel->progs.filter_kern, &opts_out) ==
      NULL) {
    goto cleanup_open_load;
  };

  /* the bpf programs stay attached to the kernel until the userspace program
   * that attached them exits. once 20 seconds are up, the above hooks are
   * detached.
   *
   * you can `pin` an attached bpf program using `bpftool`, by pinning the
   * program while its attached. assuming this program is attached by the name
   * `filter_kern` (list attached programs with `bpftool prog list`), pin it
   * using `bpftool prog pin name filter_kern /sys/fs/bpf/filter_kern_pin`
   *
   * then, the bpf program will detach when the above file is deleted and this
   * userspace program exited. */
  sleep(20);

cleanup_open_load:
  filter_kern_bpf__destroy(skel);
  return 0;
}
