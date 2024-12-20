// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <libbpf.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <bpf.h>
#include <stdarg.h>
#include "DoS_detection.skel.h"
#include <linux/types.h>

int INTERFACE = 1;

#define MAX_TYPE_LEN 4


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
    int map_ip = 0;
    int map_port = 0;
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
                ret = bpf_map_update_elem(map_config,udp,sizeof(udp),&udp_packets,sizeof(udp_packets),BPF_ANY);
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nell'aggiornamento dell'elemento nella mappa BPF: %s\n", strerror(errno));
                return ret;
                }
            }
            // Legge tcp_packets
            else if (strncmp(line, "tcp_packets:", 12) == 0) {
                tcp_packets = atoi(line + 12);
                ret = bpf_map_update_elem(map_config,tcp,sizeof(tcp),&tcp_packets,sizeof(tcp_packets),BPF_ANY);
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
    struct bpf_map *map_config;
    struct bpf_map *udp_map_packets;
    struct bpf_map *tcp_map_packets;
	int err;
    char tcp[MAX_TYPE_LEN] = "tcp";
    char udp[MAX_TYPE_LEN] = "udp";

	
	/* Open load and verify BPF application */
	skel = DoS_detection_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    // Ottieni le mappa BPF per la OPEN
    map_config = skel->maps.CONFIG_MAP;
    if (map_ip < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    udp_map_packets = skel->maps.UDP_PACKETS_MAP;
    if (map_port < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    tcp_map_packets = skel->maps.TCP_PACKETS_MAP;
    if (map_port < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor della mappa BPF.\n");
        goto cleanup;
    }
    //popolo la mappa
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

    __U32_TYPE cleanup_int = 0;
    int ret;
	while (!stop) {
        ret = bpf_map__update_elem(udp_map_packets,udp,sizeof(udp),&cleanup_int,sizeof(cleanup_int),BPF_ANY); //NEL KERNEL DEVE ESSERE BPF_EXIST
                if (ret < 0) {
                // Errore nell'aggiornamento dell'elemento
                fprintf(stderr, "Errore nel cleanup periodico della mappa: %s\n", strerror(errno));
                goto cleanup;
                }
        ret = bpf_map__update_elem(tcp_map_packets,tcp,sizeof(tcp),&cleanup_int,sizeof(cleanup_int),BPF_ANY); //NEL KERNEL DEVE ESSERE BPF_EXIST
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