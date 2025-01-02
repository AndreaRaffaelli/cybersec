#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TCP 0
#define UDP 1

// Definizione del Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} ringbuf SEC(".maps");

// Struttura dell'evento da scrivere nel ring buffer
struct packet_info {
    __u32 ip;
    __u16 port;
    int protocol;
};

// Blacklist:
struct {
     __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Dimensione massima della blacklist
    __type(key, __u32); // IP è un u32
    __type(value, int);
} blacklist SEC(".maps");



#define CHECK_BOUNDS(ptr, size) ((void *)(ptr) + (size) > data_end)

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    if (ctx->ingress_ifindex != 0) {
        __u32 *ip_value;
        int flag_proto = 0; //0 == tcp, 1 ==udp
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth = data;
        __u64 nh_off = sizeof(*eth);

        if (data + nh_off > data_end){
//            bpf_printk("Esce qui: if (data + nh_off > data_end)");            
            return XDP_DROP;
        }

        if (eth->h_proto != bpf_htons(ETH_P_IP)){
//            bpf_printk("Esce qui: if (eth->h_proto != bpf_htons(ETH_P_IP))");            
            return XDP_PASS;
        }

        struct iphdr *ip = data + nh_off;
        if (CHECK_BOUNDS(ip, sizeof(*ip))){
//            bpf_printk("Esce qui: if (CHECK_BOUNDS(ip, sizeof(*ip)))"); 
            return XDP_DROP;
        }

        struct packet_info *entry = bpf_ringbuf_reserve(&ringbuf, sizeof(struct packet_info), 0);
        if (!entry){
//            bpf_printk("Esce qui: if (!entry)"); 
            return XDP_DROP;
        }

        __u16 src_port=0;
        __u32 src_ip = ip->saddr;
        entry->ip = src_ip;

        ip_value = bpf_map_lookup_elem(&blacklist,&src_ip);
/*         if(!ip_value){
            bpf_printk("Esce qui: if(!ip_value)"); 
            bpf_ringbuf_discard(entry, 0);
            return XDP_DROP;
        } */
        if(ip_value && *ip_value == 1){
            bpf_printk("Ip in blacklist: droppato"); 
            bpf_ringbuf_discard(entry, 0);
            return XDP_DROP;
        }

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (CHECK_BOUNDS(tcp, sizeof(*tcp))){
//                bpf_printk("Esce qui: if (CHECK_BOUNDS(tcp, sizeof(*tcp)))"); 
                bpf_ringbuf_discard(entry, 0);
                return XDP_DROP;
            }
            src_port = bpf_ntohs(tcp->dest);
            flag_proto = TCP;
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if (CHECK_BOUNDS(udp, sizeof(*udp))){
//                bpf_printk("Esce qui: if (CHECK_BOUNDS(udp, sizeof(*udp)))");
                bpf_ringbuf_discard(entry, 0);
                return XDP_DROP;
            }
            src_port = bpf_ntohs(udp->dest);
            flag_proto = UDP;
        }


        bpf_printk("IP: %d\n", src_ip); 
        bpf_printk("PORT: %u\n", src_port);
        bpf_printk("PROTOCOLLO: %u\n", flag_proto); 

        //entry->ip = src_ip;
        entry->port = src_port;
        entry->protocol = flag_proto;

        bpf_ringbuf_submit(entry, 0);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
