#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 256
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 2
#define MAX_ENTRIES_PACKETS 1
#define MAX_TYPE_LEN 4

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES); 
    __type(key, char[MAX_TYPE_LEN]);
    __type(value, __u32);
} CONFIG_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES); 
    __type(key, char[MAX_TYPE_LEN]);
    __type(value, __u32);
} UDP_PACKETS_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES); 
    __type(key, char[MAX_TYPE_LEN]);
    __type(value, __u32);
} TCP_PACKETS_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(int));
    __uint(value_size, MAX_PATH_LEN);
} udp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(int));
    __uint(value_size, MAX_PATH_LEN);
} tcp_map SEC(".maps");

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    int key = 0;
    char *udp = bpf_map_lookup_elem(&udp_map, &key);
    char *tcp = bpf_map_lookup_elem(&tcp_map, &key);

    if (!udp || !tcp)
        return XDP_ABORTED;

    __builtin_memcpy(udp, "udp", 4);
    __builtin_memcpy(tcp, "tcp", 4);

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (void *)(ip + 1);
        if ((void *)(tcp_hdr + 1) > data_end)
            return XDP_DROP;
        // Gestione TCP
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (void *)(ip + 1);
        if ((void *)(udp_hdr + 1) > data_end)
            return XDP_DROP;
        // Gestione UDP
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
