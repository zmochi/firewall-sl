## Makefile

Code itself is fairly self explanatory, BPF programs are compiled into special BTF-bytecode object files and then loaded JIT into the kernel (After passing the verifier when loading).

This Makefile is complicated since it allows compiling and generating a skeleton for more than one eBPF program, by simply adding files to `KERN_FILES`.

## `vmlinux.h`
`vmlinux.h` is generated through the Makefile (see Makefile target `vmlinux`), and contains most definitions (structs, functions) from kernel needed for eBPF programs.

Note that `vmlinux.h` does not include C `#define`'s and they must be defined manually in the BPF program.

## `filter_kern.c`
This is the BPF program that is loaded into the kernel, and filters packets. It's loaded by the userspace program `filter_user.c` and is attached to specific netfilter hooks there. So all the kernel BPF program needs to do is drop the packet.

First we include `vmlinux.h` for definition of `struct bpf_nf_ctx`, which is the context passed to the BPF program when it's triggered.
```c
#include "vmlinux.h"
```

Then, define `NF_DROP` - the value that should be returned when the packet is dropped. `vmlinux.h` excludes these `#define`'s.

```c
#define NF_DROP 0
```

Since the BPF program is first compiled into bytecode and then loaded to the kernel, provide a hint with `SEC()` that this is a netfilter program and should be loaded into netfilter in the kernel. It's possible this isn't necessary since the userspace program already decides where to load this program in the kernel.

```c
SEC("netfilter") /* hint to BPF loader that this is an netfilter BPF program */
```

This is the function that is triggered in the kernel, simply drop the packet when it reaches the hook in netfilter.

License must be defined to use some bpf helper functions, it's possible this is not necessary since no helper functions are used here.

```c
int filter_kern(const struct bpf_nf_ctx *ctx) { return NF_DROP; }

char LICENSE[] SEC("license") = "GPL";
```

## filter_kern.skel.h

The skeleton file is generated from the BPF program bytecode by `bpftool` and contains helper functions for loading and attaching the BPF program, definitions of maps in the BPF program and so on.

It is used in the userspace program `filter_user.c` to load the BPF program into the kernel.

## filter_user.c

Necessary includes:

```c
#include "filter_kern.skel.h"
#include <unistd.h> /* sleep() */
```

These values must be defined manually since I couldn't find a header whicn defines them.

```c
#define NFPROTO_IPV4 2
#define NF_INET_LOCAL_IN 1
#define NF_INET_LOCAL_OUT 3
```

Main function. `struct filter_kern_bpf` is defined in the skeleton header file, the name template is `struct <progname>_bpf`. After the program is loaded, it contains information about the BPF program.

```c
int main() {
  struct filter_kern_bpf *skel;
  int err;

  /* can also use bpf_object__open_file() to directly open the bpf object file
   * must destroy this later with filter_bpf__destroy() */
  skel = filter_kern_bpf__open_and_load();
  if (skel == NULL) {
    exit(1);
  }
```

Define where to attach the BPF program, `struct bpf_netfilter_opts` is defined in the skeleton header file, specifically for defining where to attach netfilter bpf programs.

After defining the structs, attach the program to both netfilter hooks.

```c
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
```

The bpf programs stay attached to the kernel until the userspace program
that attached them exits. Once 20 seconds are up, the above hooks are
detached.

Sidenote: You can `pin` an attached bpf program using `bpftool`, by pinning the
program while its attached. Assuming this program is attached by the name
`filter_kern` (list attached programs with `bpftool prog list`), pin it
using `bpftool prog pin name filter_kern /sys/fs/bpf/filter_kern_pin`

This adds to the reference count of the BPF program. When the reference count reached 0, the program is removed.

If this is done, the bpf program will detach when the above file is deleted AND this
userspace program exited.

```c
  sleep(20);
```

Cleanup at the end:

```c
cleanup_open_load:
  filter_kern_bpf__destroy(skel);
  return 0;
}
```
