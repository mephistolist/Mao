#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

#define MAX_PORTS 1024

char LICENSE[] SEC("license") = "GPL";

/* Hash map for ports to be hidden from bind attempts */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} hidden_ports SEC(".maps");

/* Example: attach to tcp_close (commonly present in kernels) */
SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk) {
    __u16 lport = 0;

    if (!sk)
        return 0;

    BPF_CORE_READ_INTO(&lport, sk, __sk_common.skc_num);

    if (bpf_map_lookup_elem(&hidden_ports, &lport)) {
        bpf_printk("hidess: tcp_close on hidden port %d\n", lport);
    }

    return 0;
}
