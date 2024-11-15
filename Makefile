CC = clang
C_FILE = filter.c
OBJ_FILE = filter.bpf.o
KERN_PROGNAME = filter
KERN_PROGPATH = /sys/fs/bpf/$(KERN_PROGNAME)
CFLAGS = --target=bpf -O2 -Wall -I/usr/include/$(shell uname -m)-linux-gnu -g

all: $(C_FILE)
	$(CC) $(CFLAGS) -c $(C_FILE) -o $(OBJ_FILE)
	llvm-strip -g $(OBJ_FILE) # -g on compilation includes debug information but it also necessary for bpf_core_read (CO-RE). this strips unnecessary debug information from the object file
	bpftool prog load $(OBJ_FILE) $(KERN_PROGPATH)


clean:
	rm $(KERN_PROGPATH)

.PHONY: clean
