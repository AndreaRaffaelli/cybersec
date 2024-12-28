#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Definizione del Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} ringbuf SEC(".maps");

// Struttura dell'evento da scrivere nel ring buffer
struct event_t {
    __u32 ip;
    __u16 port;
    char protocol[4]; // "tcp" o "udp"
};


// Blacklist:
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // IP è un u32
    __uint(max_entries, 1024); // Dimensione massima della blacklist
} blacklist SEC(".maps");

/* TODO:*/
// - lookup blacklist




SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth); 
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    struct event_t *event;

    // Riserva spazio nel ring buffer
    event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_t), 0);
    if (!event)
        return XDP_PASS; // Buffer pieno o errore

    // Popola l'IP e la Porta
    event->ip = ip->saddr;
    event->port = 0;  // Imposta un valore di default per la porta, sarà sovrascritto più avanti

    if (ip->protocol == IPPROTO_TCP) { 
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        event->port = bpf_ntohs(tcp->dest);
        bpf_probe_read_str(event->protocol, sizeof(event->protocol), "tcp");

        // Stampa di debug
        bpf_printk("TCP: IP=%d, Port=%u\n", event->ip, event->port);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        event->port = bpf_ntohs(udp->dest);
        bpf_probe_read_str(event->protocol, sizeof(event->protocol), "udp");

        // Stampa di debug
        bpf_printk("UDP: IP=%d, Port=%u\n", event->ip, event->port);
    }

    // Scrive l'evento nel ring buffer
    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
