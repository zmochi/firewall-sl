CC = clang

USER_FILES = fw_sl_user.c
KERN_FILES = fw_sl_kern.c
KERN_OBJ_FILES = $(patsubst %.c,%.bpf.o,$(KERN_FILES))

CFLAGS = --target=bpf -O2 -Wall -I/usr/include/$(shell uname -m)-linux-gnu -g

all: kern user

user: fw_sl_user.c
	clang $< -lbpf -o filter

kern: $(KERN_OBJ_FILES)

%.bpf.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	# -g on compilation includes debug information but it also necessary for bpf_core_read (CO-RE). this strips unnecessary debug information from the object file
	llvm-strip -g $@
	sudo bpftool gen skeleton $@ > $(patsubst %.bpf.o,%.skel.h,$@)

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	sudo rm -f *.bpf.o *.skel.h

.PHONY: clean
