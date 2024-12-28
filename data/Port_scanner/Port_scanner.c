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


static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

// Ringbuffer:
struct event_t {
    __u32 ip;
    __u16 port;
    char protocol[4];
};

static IPMap *ipMap;

static volatile struct blacklist {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 1024);
} blacklist;


// Funzione per aggiungere una porta a un dato IP
void add_port_to_ip(__u32 ip, __u16 port, const char *protocol) {
    char ip_str[MAX_IP_LENGTH];
    inet_ntop(AF_INET, &ip, ip_str, MAX_IP_LENGTH);

    // Cerca l'IP nella mappa
    for (size_t i = 0; i < ipMap->size; i++) {
        if (strcmp(ipMap->entries[i].ip, ip_str) == 0) {
            PortList *portList = &ipMap->entries[i].portList;

            // Verifica se la porta è già presente
            for (size_t j = 0; j < portList->size; j++) {
                if (portList->ports[j] == port) {
                    return; // Porta già presente, nessuna duplicazione
                }
            }

            // Verifica numero massimo di porte
            if (portList->size == portList->capacity) {
                fprintf(stderr, "Troppe porte visitate dall'IP: %s, aggiunto alla blacklist.\n", ip_str);
                // Aggiungi l'IP alla blacklist
                bpf_map_update_elem(&blacklist, &ip, BPF_ANY);
                return; // Interrompi l'elaborazione
            }

            // Aggiungi la nuova porta
            portList->ports[portList->size++] = port;
            return;
        }
    }

    // IP non trovato, aggiungi un nuovo IP nella mappa usando add_ip_entry
    add_ip_entry(ipMap, ip_str, port);
}

int main(int argc, char **argv)
{
    int fd;
    struct bpf_xdp_attach_opts *xdp_opts=malloc(sizeof(struct bpf_xdp_attach_opts));
	struct DoS_detection_bpf *skel;
    struct bpf_map *map_config; // Qui ci sono le treshold
    struct bpf_map *udp_map_packets; // Qui conto tutti i pacchetti arrivati
    struct bpf_map *tcp_map_packets; // Qui conto tutti i pacchetti arrivati
	int err;
    char tcp[MAX_TYPE_LEN] = "tcp";
    char udp[MAX_TYPE_LEN] = "udp";

    int buffer_fd;
    struct ring_buffer *rb = NULL;

    // Inizializza la mappa IP
    ipMap = init_ip_map();
	
	/* Open load and verify BPF application */
	skel = Port_scanner_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    // Ottieni ring buffer
    buffer_fd = bpf_map__fd(skel->maps.ringbuf);
    if (buffer_fd < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
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
		goto cleanup;
	}
    xdp_opts->old_prog_fd=fd;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler\n");
		goto cleanup;
	}

	printf("Successfully started! pleas type ctrl+C for shutting down the module \n ");

    // Leggi continuamente dal ring buffer e aggiorna la mappa
     while (!stop) {
       fprintf(stderr,".");
       sleep(1);
    }



    __U32_TYPE cleanup_int = 1;
    int ret;
	//Ciclo attivo !!! Bocciato a sistemi operativi
    

cleanup:
    destroy_ip_map(ipMap);
    bpf_xdp_detach(INTERFACE, BPF_ANY,xdp_opts);  //forse bisogna specificarla nel file config
    Port_scanner_bpf__destroy(skel);
	return -err;

}
