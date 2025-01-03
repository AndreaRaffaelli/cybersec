#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// farlo whitelist

#define MAX_ENTRIES 2
#define MAX_IP_ENTRIES 1000
#define MAX_ENTRIES_PACKETS 1
#define MAX_CHAR_LEN 5
#define MAX_TYPE_LEN 4

// struct log

struct log_entry
{
    __u32 ip;
    __u16 port;
    int proto_type; // 0 tcp, 1 udp
    int pass;       // 0 passed, 1 dropped
    __u64 num;       // packet number in the window time
};

// Dichiarazione del Ring Buffer
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB di buffer
} ringbuf SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, char[MAX_TYPE_LEN]);
    __type(value, __u32);
} CONFIG_MAP SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, __u32);
    __type(value, __s64);
} IP_NUM_MAP SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
} IP_TIME_MAP SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, char[MAX_CHAR_LEN]);
    __type(value, __u32);
} TIME_MAP SEC(".maps");

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx)
{

    if (ctx->ingress_ifindex != 0)
    {

        char udp_key[MAX_TYPE_LEN] = "udp";
        char tcp_key[MAX_TYPE_LEN] = "tcp";
        int flag_proto = 0; // 0 == tcp, 1 ==udp
        __u64 flag_num = 0;
        int flag_pass = 0;
        int *value_tresh_tcp;
        int *value_tresh_udp;

        value_tresh_tcp = bpf_map_lookup_elem(&CONFIG_MAP, &tcp_key); // Leggo le mappa in Userspace
        value_tresh_udp = bpf_map_lookup_elem(&CONFIG_MAP, &udp_key); // Leggo le mappa in Userspace
        // prendi subito le tresh

        char time_key[MAX_CHAR_LEN] = "time";
        __u64 *value;
        __u64 updated_value;
        __u32 *ip_time;
        __u32 *time;
        __s64 clean_value = 1;
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        __u64 nh_off;
        __u16 src_port;
        struct ethhdr *eth = data;
        nh_off = sizeof(*eth);
        struct log_entry *entry;
        int ret;

        if (data + nh_off > data_end)
            return XDP_DROP;

        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = data + nh_off;
        if (ip + 1 > data_end)
            return XDP_DROP;

        if (ip->protocol == IPPROTO_TCP)
        { // LEGGO il protocollo
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 > data_end)
                return XDP_DROP;
            src_port = bpf_ntohs(tcp->dest);
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            flag_proto = 1;
            if (udp + 1 > data_end)
                return XDP_DROP;
            src_port = bpf_ntohs(udp->dest);
        }
        // Indirizzo IP sorgente
        __u32 src_ip = ip->saddr;

        // DEBUG - log nel ringbuf
        // Alloca spazio nella ring buffer
        entry = bpf_ringbuf_reserve(&ringbuf, sizeof(struct log_entry), 0);
        if (!entry)
        {
            // ignoro il fallimento, buffer pieno perderò dati // Fallimento nella riserva
            return XDP_DROP;
        }

        /*             bpf_printk("IP: %d\n", src_ip);
                    bpf_printk("PORT: %u\n", src_port); */

        // INIZIO CONTROLLI

        /* se trova l'ip nella mappa controlla il time_ip sia uguale al time, se non lo è aggiorna sia time (al tempo del vero time)
        sia numero pacchetto (a 1), se lo è aggiorna solo il numero
        se non lo trova lo aggiorna aggiungendo ip alla mappa con num a 1 e time_ip uguale a time

        */

        value = bpf_map_lookup_elem(&IP_NUM_MAP, &src_ip);

        // debug

        if (value)
        { // l'ip è stato trovato
            // bpf_printk("pacchetti segnati per l'IP: %u\n", *value);
            ip_time = bpf_map_lookup_elem(&IP_TIME_MAP, &src_ip);
            time = bpf_map_lookup_elem(&TIME_MAP, &time_key);

            if (ip_time && time && (*ip_time < *time))
            { // TEMPO DIVERSO AGGIORNARE TUTTO
                // bpf_printk("IP_TIME: %lld\n", *ip_time);
                // bpf_printk("REAL_TIME: %u\n", *time);
                ret = bpf_map_update_elem(&IP_NUM_MAP, &src_ip, &clean_value, BPF_ANY);
                __u32 time_map = *time;
                ret = bpf_map_update_elem(&IP_TIME_MAP, &src_ip, &time_map, BPF_ANY);
                flag_num = 1;
                flag_pass = 0;
            }
            if (ip_time && time && (*ip_time == *time))
            { // TEMPO UGUALE AGGIORNA NUM
                // bpf_printk("IP_TIME: %u\n", *ip_time);
                // bpf_printk("REAL_TIME: %u\n", *time);
                updated_value = *value + 1;
                // bpf_printk("UPDATED VALUE: %lld\n", updated_value);
                ret = bpf_map_update_elem(&IP_NUM_MAP, &src_ip, &updated_value, BPF_ANY);
                flag_num = updated_value;
                if (flag_proto == 0) // TCP
                {
                    if (value_tresh_tcp)
                    {
                        // bpf_printk("LA TRESH VALUE TCP è: %u\n", *value_tresh_tcp);
                        if (updated_value >= *value_tresh_tcp)
                        {
                            // bpf_printk("LA TRESH VALUE TCP è: %d\n", *value_tresh_tcp);
                            // bpf_printk("droppo un pacchetto TCP\n");
                            flag_pass = 1;
                            if (entry)
                            {
                                entry->ip = src_ip;
                                entry->port = src_port;
                                entry->proto_type = flag_proto;
                                entry->pass = flag_pass;
                                entry->num = flag_num;
                            }
                            // Sottometti l'entry al buffer
                            bpf_ringbuf_submit(entry, 0); // DEVE ESSERE DEALLOCATO PRIMA DELL?USCITA
                            return XDP_DROP;              // Comando di drop
                        }
                        else
                        {
                            flag_pass = 0;
                        }
                    }
                }
                else // UDP
                {
                    if (value_tresh_udp)
                    {
                        // bpf_printk("LA TRESH VALUE TCP è: %u\n", *value_tresh_tcp);
                        if (updated_value >= *value_tresh_udp)
                        {
                            // bpf_printk("LA TRESH VALUE TCP è: %d\n", *value_tresh_tcp);
                            // bpf_printk("droppo un pacchetto UDP\n");
                            flag_pass = 1;
                            if (entry)
                            {
                                entry->ip = src_ip;
                                entry->port = src_port;
                                entry->proto_type = flag_proto;
                                entry->pass = flag_pass;
                                entry->num = flag_num;
                            }
                            // Sottometti l'entry al buffer
                            bpf_ringbuf_submit(entry, 0); // DEVE ESSERE DEALLOCATO PRIMA DELL?USCITA
                            return XDP_DROP;              // Comando di drop
                        }
                        else
                        {
                            flag_pass = 0;
                        }
                    }
                }
            }
        }
        else
        { // IL RECORD NON C?é si CREA
            ret = bpf_map_update_elem(&IP_NUM_MAP, &src_ip, &clean_value, BPF_ANY);
            __u32 time_map = 1;
            ret = bpf_map_update_elem(&IP_TIME_MAP, &src_ip, &time_map, BPF_ANY);
            // bpf_printk("RECORD ADDEDD\n");
            flag_num = 1;
            flag_pass = 0;
        }

        if (entry)
        {
            entry->ip = src_ip;
            entry->port = src_port;
            entry->proto_type = flag_proto;
            entry->pass = flag_pass;
            entry->num = flag_num;
        }
        // Sottometti l'entry al buffer
        bpf_ringbuf_submit(entry, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
