#include <vmlinux.h>
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//farlo whitelist


#define MAX_ENTRIES 2
#define MAX_ENTRIES_PACKETS 1
#define MAX_TYPE_LEN 4


//RECEIVE IP and PORTS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); 
    __type(key, char[MAX_TYPE_LEN]);
	__type(value, __u32);
} CONFIG_MAP SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); 
    __type(key, char[MAX_TYPE_LEN]);
	__type(value, __u32);
} UDP_PACKETS_MAP SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES); 
    __type(key, char[MAX_TYPE_LEN]);
	__type(value, __u32);
} TCP_PACKETS_MAP SEC(".maps") ;

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {

    if (ctx->ingress_ifindex != 0) {
        
        char udp_key[MAX_TYPE_LEN] = "udp";
        char tcp_key[MAX_TYPE_LEN] = "tcp";
        int *value_tresh_tcp;
        int *value_tresh_udp;

        value_tresh_tcp = bpf_map_lookup_elem(&CONFIG_MAP,&tcp_key); // Leggo le mappa in Userspace
        value_tresh_udp = bpf_map_lookup_elem(&CONFIG_MAP,&udp_key); // Leggo le mappa in Userspace
        //prendi subito le tresh
        
        //Giri strani che devi fare per forza
        int *value_udp;
        int *value_tcp;
        __u32 updated_tcp;
        __u32 updated_udp;
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        __u64 nh_off;
        struct ethhdr *eth = data;
        nh_off = sizeof(*eth);
        
        
        if (data + nh_off > data_end)
            return XDP_DROP;

        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = data + nh_off; 
        if (ip + 1 > data_end)
            return XDP_DROP;

        if (ip->protocol == IPPROTO_TCP) { // LEGGO il protocollo
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if (tcp + 1 > data_end)
                return XDP_DROP;
            
            // Indirizzo IP sorgente
            __u32 src_ip = ip->saddr;
            
            // Porta destinazione TCP
            __u16 src_port =bpf_ntohs(tcp->dest);
            

            //DEBUG - stampa in log bpf
            bpf_printk("IP: %d\n", src_ip); 
            bpf_printk("PORT: %u\n", src_port);
            
            // AGGIORNA NUMERO PACCHETTI NEL SECONDO
            value_tcp = bpf_map_lookup_elem(&TCP_PACKETS_MAP,&tcp_key);
            //debug
            if(value_tcp){
            //bpf_printk("value  tcp: %u\n", *value_tcp);
            updated_tcp = *value_tcp + 1;
            bpf_printk("value  tcp updated: %u\n", updated_tcp);
            int ret = bpf_map_update_elem(&TCP_PACKETS_MAP, &tcp_key, &updated_tcp, BPF_EXIST);
            }

            //CONTROLLA CHE SIANO SOTTO LA TRESH
            if(value_tresh_tcp){
            //bpf_printk("LA TRESH VALUE TCP è: %u\n", *value_tresh_tcp);
            if(updated_tcp >= *value_tresh_tcp){
                bpf_printk("LA TRESH VALUE TCP è: %d\n", *value_tresh_tcp);
                bpf_printk("droppo un pacchetto TCP\n");
                return XDP_DROP; // Comando di drop
            }
            } 


        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if (udp + 1 > data_end)
                return XDP_DROP;
            
            // Indirizzo IP sorgente
            __u32 src_ip = ip->saddr;  //potrebbero essere utili
            
            // Porta destinazione UDP
            __u16 src_port = udp->dest; //potrebbero essere utili

            //DEBUG

            bpf_printk("IP: %d\n", src_ip);
            bpf_printk("PORT: %u\n", src_port);
            
            
            // AGGIORNA NUMERO PACCHETTI NEL SECONDO
            value_udp = bpf_map_lookup_elem(&UDP_PACKETS_MAP,&udp_key);
            //debug
            if(value_udp){
              //bpf_printk("value  udp: %u\n", *value_udp);
              updated_udp = *value_udp + 1;
              bpf_printk("value  udp updated: %u\n", updated_udp);
              int ret = bpf_map_update_elem(&UDP_PACKETS_MAP, &udp_key, &updated_udp, BPF_EXIST);
            }

            //CONTROLLA CHE SIANO SOTTO LA TRESH
            if(value_tresh_udp){
            //bpf_printk("LA TRESH VALUE UDP è: %u\n", *value_tresh_udp);
            if(updated_udp >= *value_tresh_udp){
                bpf_printk("LA TRESH VALUE UDP è: %d\n", *value_tresh_udp);
                bpf_printk("droppo un pacchetto UDP\n");
                return XDP_DROP;
            } 
          }
        }
    }
    
    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
