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
#define MAX_CHAR_LEN 5

struct log_final{ //LOG PRODUZIONE CHE INDICA NUM OACCHETTO DROPPATI
    
    long num_tcp;
    long num_udp;
    long num_total; 
    long num_dropped;
};

struct log_final log;

struct log_final log = {0,0,0,0};


struct log_entry {
    int ip;
    int port;
    int proto_type; //0 tcp, 1 udp
    int pass; //0 passed, 1 dropped
    long num; //packet number in the window time
};



static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}



void bump_memlock_rlimit() {
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
}


// Callback per gestire gli eventi ricevuti dalla ring buffer (PRODUCTION)
int handle_event(void *ctx, void *data, size_t size) {
    struct log_entry *event = (struct log_entry *)data;
    if(event->proto_type == 0){ //tcp
        log.num_tcp ++;
    }else{
        log.num_udp ++;
    }
    if(event->pass == 1){
        log.num_dropped++;
    }
    log.num_total++;
    return 1;
}


//DEBUG MODE
/*int handle_event(void *ctx, void *data, size_t size) {
    struct log_entry *event = (struct log_entry *)data;
    fprintf(stdout, "IP: %d, PORT: %d, PROTO: %d (0 tcp, 1 udp), num: %lx, drop: %d (0 pass, 1 drop)", event->ip, event ->port, event->proto_type, event->num, event->pass);
    return 1;
}*/



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

void printLog(){
    fprintf(stdout, "DoS detector report: \n");
    fprintf(stdout, "TOTAL PACKETS: %lx\n", log.num_total);
    fprintf(stdout, "TCP: %lx\n", log.num_tcp);
    fprintf(stdout, "UDP: %lx\n", log.num_udp);
    fprintf(stdout, "DROPPED PACKETS: %lx\n", log.num_dropped);
}

int main(int argc, char **argv)
{
    int fd;
    struct bpf_xdp_attach_opts *xdp_opts=malloc(sizeof(struct bpf_xdp_attach_opts));
	struct DoS_detection_bpf *skel;
    struct bpf_map *map_config; // Qui ci sono le treshold
    struct bpf_map *ip_num_map; // 
    struct bpf_map *ip_time_map; // 
    struct bpf_map *time_map; // 
	int buffer_fd;
    struct ring_buffer *rb = NULL;
    int err;
    char tcp[MAX_TYPE_LEN] = "tcp";
    char udp[MAX_TYPE_LEN] = "udp";
    char time_key[MAX_CHAR_LEN] = "time";

	
	/* Open load and verify BPF application */
	skel = DoS_detection_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    // Ottieni le mappa BPF per la OPEN
    map_config = skel->maps.CONFIG_MAP;
    if (map_config < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    ip_num_map = skel->maps.IP_NUM_MAP;
    if (ip_num_map < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    ip_time_map = skel->maps.IP_TIME_MAP;
    if (ip_time_map < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    time_map = skel->maps.TIME_MAP;
    if (time_map < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
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

    //popolo la mappa // LEGGO LE TRESHOLDs
    if((populate_map("config.txt",map_config))!=0){
        fprintf(stderr, "Errore nel popolare la mappa \n");
        goto cleanup;
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

    __U32_TYPE cleanup_int = 1;
    int ret;
    __u32 time = 1;
	//Ciclo attivo !!! Bocciato a sistemi operativi
    
    while (!stop) { // Ogni secondo faccio cleanup
        ret = bpf_map__update_elem(time_map,&time_key,sizeof(time_key),&time,sizeof(time),BPF_ANY); //NEL KERNEL DEVE ESSERE BPF_EXIST
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nel cleanup periodico della mappa: %s\n", strerror(errno));
                goto cleanup;
                }
        

        /*ret = ring_buffer__poll(rb, 0); //polling buffer
        if (ret < 0) {
            fprintf(stderr, "Polling error: %d\n", err);
            break;
        }*/
        time++; //aggiorno tempo
		fprintf(stderr, ".");
		sleep(1);
	}
    
cleanup:
    printLog();
    ring_buffer__free(rb);
    bpf_xdp_detach(INTERFACE, BPF_ANY,xdp_opts);  //forse bisogna specificarla nel file config      
	DoS_detection_bpf__destroy(skel);
	return -err;

}
