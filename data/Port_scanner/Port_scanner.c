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

#include "DoS_detection.skel.h"
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

// Blacklist:
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // IP è un u32
    __uint(max_entries, 1024); // Dimensione massima della blacklist
} blacklist SEC(".maps");



// Funzione per aggiungere una porta a un dato IP
void add_port_to_ip(struct ip_map *map, __u32 ip, __u16 port, const char *protocol) {
    // Cerca l'IP nella mappa
    for (size_t i = 0; i < map->size; i++) {
        if (map->ip_map[i].ip == ip) {
            // Trova l'IP, aggiungi la stringa "IP:PORT"
            char port_str[128];
            snprintf(port_str, sizeof(port_str), "%s:%u", inet_ntoa(*(struct in_addr *)&ip), port);

            // Verifica se la porta è già presente
            for (size_t j = 0; j < map->ip_map[i].size; j++) {
                if (strcmp(map->ip_map[i].ports[j], port_str) == 0) {
                    return;  // Porta già presente, nessuna duplicazione
                }
            }

            // Verifica numero massimo di porte ispezionate
            if (map->ip_map[i].size == map->ip_map[i].capacity) {
                __u32 ip_to_blacklist = map->ip_map[i].ip;

                // Aggiungi l'IP alla blacklist
                bpf_map_update_elem(&blacklist, &ip_to_blacklist, BPF_ANY);
                return;    // Troppe porte visitate dallo stesso ip -> aggiunto alla blacklist
            }

/* TODO:*/
// - lookup lato kernel per vedere se l'ip è nella blacklist -> lo droppiamo


            // Aggiungi la nuova stringa "IP:PORT"
            map->ip_map[i].ports[map->ip_map[i].size] = strdup(port_str);
            map->ip_map[i].size++;
            return;
        }
    }

    // IP non trovato, aggiungi un nuovo IP nella mappa
    if (map->size == map->capacity) {
        map->capacity *= 2;
        map->ip_map = realloc(map->ip_map, map->capacity * sizeof(struct ip_map));
    }

    map->ip_map[map->size].ip = ip;
    map->ip_map[map->size].ports = malloc(4 * sizeof(char *));  // Inizializza l'array per un massimo di 4 porte
    map->ip_map[map->size].size = 0;
    map->ip_map[map->size].capacity = 4;

    // Aggiungi la porta al nuovo IP
    char port_str[128];
    snprintf(port_str, sizeof(port_str), "%s:%u", inet_ntoa(*(struct in_addr *)&ip), port);
    map->ip_map[map->size].ports[map->ip_map[map->size].size] = strdup(port_str);
    map->ip_map[map->size].size++;

    map->size++;
}

// Funzione per leggere il ring buffer e popolare la mappa
int read_ringbuf_and_populate_map(int ring_fd, struct ip_map *map) {
    struct event_t *event;
    ssize_t bytes_read;

    bytes_read = bpf_ringbuf_poll(ring_fd, (void **)&event, sizeof(struct event_t), 0);
    if (bytes_read < 0) {
        if (errno == EAGAIN) {
            return 0;  // Nessun dato disponibile
        } else {
            perror("bpf_ringbuf_poll");
            return -1;
        }
    }

    // Aggiungi l'IP e la porta alla mappa
    add_port_to_ip(map, event->ip, event->port, event->protocol);

    return 0;
}

/* void bump_memlock_rlimit() {
    struct rlimit rlim;

    if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;  // Imposta il limite corrente al massimo consentito
        if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
            perror("setrlimit");
            exit(-1);
        }
    } else {
        perror("getrlimit");
        exit(-1);
    }
} */

//popolare la mappa
int populate_map(const char *config_file, struct bpf_map *map_config) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Errore nell'aprire il file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    int in_threshold_section = 0;
    __U32_TYPE udp_packets = 0;
    __U32_TYPE tcp_packets = 0;
    //int ok_value=1;
    int ret;
    char tcp[MAX_TYPE_LEN] = "tcp";
    char udp[MAX_TYPE_LEN] = "udp";
    

    while (fgets(line, sizeof(line), file)) {
        // Rimuove i caratteri di newline
        line[strcspn(line, "\r\n")] = 0;

        // Controlla se siamo nella sezione [TRESHOLD]
        if (strcmp(line, "[TRESHOLD]") == 0) {
            in_threshold_section = 1;
            continue;
        }

        // Esce dalla sezione se incontra un'altra intestazione
        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            in_threshold_section = 0;
            continue;
        }

        if (in_threshold_section) {
            // Legge udp_packets
            if (strncmp(line, "udp_packets:", 12) == 0) {
                udp_packets = atoi(line + 12);
                printf("TRESH_UDP: %u\n", udp_packets);
                ret = bpf_map__update_elem(map_config,&udp,sizeof(udp),&udp_packets,sizeof(udp_packets),BPF_ANY);
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                return ret;
                }
            }
            // Legge tcp_packets
            else if (strncmp(line, "tcp_packets:", 12) == 0) {
                tcp_packets = atoi(line + 12);
                printf( "TRESH_TCP: %u\n", tcp_packets);
                ret = bpf_map__update_elem(map_config,&tcp,sizeof(tcp),&tcp_packets,sizeof(tcp_packets),BPF_ANY);
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                return ret;
                }
            }
        }
    }

    fclose(file);

    
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

	
	/* Open load and verify BPF application */
	skel = DoS_detection_bpf__open_and_load();
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
    rb = ring_buffer__new(buffer_fd, handle_event, NULL, NULL);
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
    while (1) {
        if (read_ringbuf_and_populate_map(ring_fd, &ip_map) < 0) {
            break;
        }
    }



    __U32_TYPE cleanup_int = 1;
    int ret;
	//Ciclo attivo !!! Bocciato a sistemi operativi
    
    while (!stop) { // Ogni secondo faccio cleanup
        ret = bpf_map__update_elem(udp_map_packets,&udp,sizeof(udp),&cleanup_int,sizeof(cleanup_int),BPF_ANY); //NEL KERNEL DEVE ESSERE BPF_EXIST
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nel cleanup periodico della mappa: %s\n", strerror(errno));
                goto cleanup;
                }
        ret = bpf_map__update_elem(tcp_map_packets,&tcp,sizeof(tcp),&cleanup_int,sizeof(cleanup_int),BPF_ANY); //NEL KERNEL DEVE ESSERE BPF_EXIST
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nel cleanup periodico della mappa: %s\n", strerror(errno));
                goto cleanup;
                }
		fprintf(stderr, ".");
		sleep(1);
	}
    
cleanup:
    bpf_xdp_detach(INTERFACE, BPF_ANY,xdp_opts);  //forse bisogna specificarla nel file config      
	DoS_detection_bpf__destroy(skel);
	return -err;

}
