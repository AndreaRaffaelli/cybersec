#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Struttura per i dati dei pacchetti
struct packet_info {
    __u32 ip;
    __u16 port;
    char protocol[4];
};

// Ring buffer per i pacchetti
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} ringbuf SEC(".maps");

// Hashmap per tracciare il conteggio dei pacchetti
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // IP sorgente
    __uint(value_size, sizeof(__u32)); // Contatore
    __uint(max_entries, 1024); // Numero massimo di IP da monitorare
} packet_count SEC(".maps");

// Ring buffer per gli IP blacklistati
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} blacklist_ringbuf SEC(".maps");

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Verifica se è un pacchetto IP
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Verifica se l'IP è nella blacklist
    __u32 *blacklisted = bpf_map_lookup_elem(&packet_count, &src_ip);
    if (blacklisted && *blacklisted == 2) {
        return XDP_DROP; // Droppa il pacchetto
    }

    // Controlla il protocollo
    char protocol[4];
    struct packet_info *event;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 src_port = bpf_ntohs(tcp->dest);
        __builtin_memcpy(protocol, "tcp", 4);

        // Scrivi i dati nel ring buffer
        event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct packet_info), 0);
        if (event) {
            event->ip = src_ip;
            event->port = src_port;
            __builtin_memcpy(event->protocol, protocol, 4);
            bpf_ringbuf_submit(event, 0);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 src_port = bpf_ntohs(udp->dest);
        __builtin_memcpy(protocol, "udp", 4);

        // Scrivi i dati nel ring buffer
        event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct packet_info), 0);
        if (event) {
            event->ip = src_ip;
            event->port = src_port;
            __builtin_memcpy(event->protocol, protocol, 4);
            bpf_ringbuf_submit(event, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
