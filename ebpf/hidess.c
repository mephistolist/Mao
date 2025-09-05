#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

#define MAX_PORTS 1024

char LICENSE[] SEC("license") = "GPL";

// Hash map for ports to be hidden from bind attempts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);   // port number
    __type(value, __u8);  // dummy value
} hidden_ports SEC(".maps");

// LSM hook for socket_bind: block bind attempts on hidden ports
SEC("lsm/socket_bind")
int BPF_PROG(socket_bind_hook, struct sock *sk) {
    __u16 lport;
    BPF_CORE_READ_INTO(&lport, sk, __sk_common.skc_num);

    if (bpf_map_lookup_elem(&hidden_ports, &lport)) {
        return -EPERM; // deny the bind
    }
    return 0;
}

// Optional: kprobe for tcp_close (example only)
// This can be used to monitor or clean up, but isn’t required for hiding.
SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk) {
    __u16 lport;
    BPF_CORE_READ_INTO(&lport, sk, __sk_common.skc_num);

    if (bpf_map_lookup_elem(&hidden_ports, &lport)) {
        // For now, just trace it (no blocking here)
        bpf_printk("tcp_close on hidden port %d\n", lport);
    }
    return 0;
}
