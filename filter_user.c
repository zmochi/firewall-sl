/* see 'Learning eBPF', page 102 */
#include <linux/netfilter.h>
#include <unistd.h> /* sleep() */

int main() {
  /* filter.skel.h defines the BPF kernel program. this struct is defined in
   * filter.skel.h and is loaded with information about the BPF program in the
   * filter_bpf__open_and_load() call */
  struct filter_bpf *skel;
  int err;

  /* can also use bpf_object__open_file() to directly open the bpf object file
   * must destroy this later with filter_bpf__destroy() */
  skel = filter_bpf__open_and_load();
  if (skel == NULL) {
    exit(1);
  }

  struct bpf_netfilter_opts opts_in = {
      .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_IN, .priority = 0};
  struct bpf_netfilter_opts opts_out = {
      .pf = NFPROTO_IPV4, .hooknum = NF_INET_LOCAL_OUT, .priority = 0};

  /* attach bpf program to kernel */
  if (bpf_program__attach_netfilter(skel->progs.filter, &opts_in) == NULL) {
    goto cleanup;
  };
  // err = filter_bpf__attach(skel);
  // if (err < 0) {
  //   goto cleanup;
  // }

  sleep(20);

cleanup:
  filter_bpf__destroy(skel);
  return 0;
}
