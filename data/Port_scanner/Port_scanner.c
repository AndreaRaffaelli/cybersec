//  SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <libbpf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <bpf.h>
#include "ip_map/ip_map.h"
#include "Port_scanner.skel.h"
#include <linux/types.h>

int INTERFACE = 1;

#define MAX_TYPE_LEN 4
#define UDP 1
#define TCP 0

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


static IPMap *ipMap_tcp;
static IPMap *ipMap_udp;
struct bpf_map *blacklist_map= NULL;

struct packet_info {
    int ip;
    int port;
    int protocol;
};


// Funzione per aggiungere una porta a un dato IP
int add_port_to_ip(void *ctx, void *data, size_t len) {
    int ret = 0;
    int ret2=0;
    char ip_str[MAX_IP_LENGTH];
    struct packet_info *event = (struct packet_info *)data;
    // Conversione a STRING
    inet_ntop(AF_INET, event->ip, ip_str, MAX_IP_LENGTH);
    fprintf(stdout, "\n IP: %d, PORT: %d, PROTO: %d \n", ip_str, event->port, event->protocol);


    if( event->protocol == TCP){
        ret= add_ip_entry(ipMap_tcp, ip_str, event->port);
    }else{  //UDP
        ret= add_ip_entry(ipMap_udp, ip_str, event->port);
    }

    if(ret==2){ //ip verrà aggiunto a blacklist
        fprintf(stdout,"Pacchetto aggiunto alla blacklist: troppe richieste\n");
        ret2 = bpf_map_update_elem(blacklist_map, &event->ip, sizeof(event->ip),1, sizeof(int),BPF_ANY);
        if (ret2 < 0) {
            fprintf(stderr, "Errore nell'update della blacklist: %s\n", strerror(errno));
            return 2;
        }
    } else if(ret==1){  //porta già presente
        fprintf(stdout,"Porta gia' richiesta in precedenza\n");  
        return 1;
    } else if(ret==0){
        fprintf(stdout,"Pacchetto aggiunto per la prima volta\n");
    }

    if( event->protocol == TCP){
        print_ip_map(ipMap_tcp);
    }else{  //UDP
        print_ip_map(ipMap_udp);
    }
    fprintf(stdout, "\n\n");
   
    return 0;
}

int main(int argc, char **argv)
{
    int fd;
    struct bpf_xdp_attach_opts *xdp_opts=malloc(sizeof(struct bpf_xdp_attach_opts));
	struct Port_scanner_bpf *skel; 
	int err;
    int buffer_fd;
    struct ring_buffer *rb = NULL;



    // Inizializza la mappa IP
    ipMap_tcp = init_ip_map();
	ipMap_udp = init_ip_map(); 

	/* Open load and verify BPF application */
	skel = Port_scanner_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    //Ottieni mappa blacklist
    blacklist_map = skel->maps.blacklist;
    if (blacklist_map < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF (blacklist).\n");
        return 1;
    }

    // Ottieni ring buffer
    buffer_fd = bpf_map__fd(skel->maps.ringbuf);
    if (buffer_fd < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        return 1;
    }

      // Configura la ring buffer
    rb = ring_buffer__new(buffer_fd, add_port_to_ip, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    
    fd = bpf_program__fd(skel->progs.xdp_ingress);
    xdp_opts->sz = sizeof(struct bpf_xdp_attach_opts);
    xdp_opts->old_prog_fd=-1;
    err = bpf_xdp_attach(INTERFACE,fd,BPF_ANY,xdp_opts);
	if (err) {
		fprintf(stderr, "Failed to attach XDP: %d\n", err);
		return 1;
	}
    xdp_opts->old_prog_fd=fd;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler\n");
		return 1;
	}

	printf("Successfully started! pleas type ctrl+C for shutting down the module \n ");

    while (!stop) {
        err = ring_buffer__poll(rb, -1);  // -1 per attendere indefinitamente
        if (err < 0) {
            fprintf(stderr, "Errore durante il polling del ring buffer: %s\n", strerror(-err));
            break;
        } 
        fprintf(stderr, ".");
        sleep(1);
    }


    // cleanup:
    fprintf(stderr, "\nExiting...\n");
    destroy_ip_map(ipMap_tcp);
    destroy_ip_map(ipMap_udp); 
    ring_buffer__free(rb);
    bpf_xdp_detach(INTERFACE, BPF_ANY,xdp_opts);  //forse bisogna specificarla nel file config
    Port_scanner_bpf__destroy(skel);
	return -err;

}
