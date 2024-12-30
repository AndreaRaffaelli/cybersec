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
    int proto_type;     //0 tcp, 1 udp
};

// Ring buffer per i pacchetti
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} ringbuf SEC(".maps");

// Hashmap per tracciare il conteggio dei pacchetti
/* struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // IP sorgente
    __uint(value_size, sizeof(__u32)); // Contatore
    __uint(max_entries, 1024); // Numero massimo di IP da monitorare
} packet_count SEC(".maps"); */

// Ring buffer per gli IP blacklistati
/* struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} blacklist_ringbuf SEC(".maps"); */

#define CHECK_BOUNDS(ptr, size) ((void *)(ptr) + (size) > data_end)

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    if (ctx->ingress_ifindex != 0) {
        int flag_proto = 0; //0 == tcp, 1 ==udp
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;
        __u64 nh_off = sizeof(*eth);

        if (data + nh_off > data_end)
            return XDP_DROP;

        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = data + nh_off;
        if (CHECK_BOUNDS(ip, sizeof(*ip)))
            return XDP_DROP;

        __u16 src_port=0;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (CHECK_BOUNDS(tcp, sizeof(*tcp)))
                return XDP_DROP;
            src_port = bpf_ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if (CHECK_BOUNDS(udp, sizeof(*udp)))
                return XDP_DROP;
            src_port = bpf_ntohs(udp->dest);
            flag_proto = 1;
        }

        __u32 src_ip = ip->saddr;

        struct packet_info *entry = bpf_ringbuf_reserve(&ringbuf, sizeof(struct packet_info), 0);
        if (!entry)
            return XDP_DROP;

        bpf_printk("IP: %d\n", src_ip); 
        bpf_printk("PORT: %u\n", src_port);
        bpf_printk("PROTOCOLLO: %u\n", flag_proto); 

        entry->ip = src_ip;
        entry->port = src_port;
        entry->proto_type = flag_proto;

        bpf_ringbuf_submit(entry, 0);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
