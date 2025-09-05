BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall
USER_CC=cc
USER_CFLAGS=-Wall
USER_LDLIBS=-lbpf -lelf -lz

BPF_PROGS = kprobe.o hidess.o
USER_PROG = loader

.PHONY: all clean load

all: $(BPF_PROGS) $(USER_PROG)

# Build BPF objects
%.o: %.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Build user loader
$(USER_PROG): loader.c
	$(USER_CC) $(USER_CFLAGS) loader.c -o $(USER_PROG) $(USER_LDLIBS)

# Load programs with bpftool
load: $(BPF_PROGS)
	sudo bpftool prog load kprobe.o /sys/fs/bpf/kprobe
	sudo bpftool prog load hidess.o /sys/fs/bpf/hidess

clean:
	rm -f $(BPF_PROGS) $(USER_PROG)
