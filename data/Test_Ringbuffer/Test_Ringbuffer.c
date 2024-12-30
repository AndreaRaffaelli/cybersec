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

#include "Test_Ringbuffer.skel.h"
#include <linux/types.h>

int INTERFACE = 1;

struct packet_info {
    int ip;
    int port;
    int protocol;
};

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


int handle_event(void *ctx, void *data, size_t len) {
    fprintf(stdout,"handle_event\n");
    struct packet_info *event = (struct packet_info *)data;
    fprintf(stdout, "\n IP: %d, PORT: %d, PROTO: %d \n", event->ip, event ->port, event->protocol);

/*     struct packet_info *event = (struct packet_info *)data;
    char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
             event->ip & 0xFF,
             (event->ip >> 8) & 0xFF,
             (event->ip >> 16) & 0xFF,
             (event->ip >> 24) & 0xFF);
    fprintf(stdout,"Packet: IP=%s, Port=%u, Protocol=%s\n", ip, event->ip, event->protocol); */
    return 1;
}

/* int handle_blacklist(void *ctx, void *data, size_t len) {
    fprintf(stdout,"handle_blacklist\n");
    __u32 *blacklisted_ip = data;
    char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
             *blacklisted_ip & 0xFF,
             (*blacklisted_ip >> 8) & 0xFF,
             (*blacklisted_ip >> 16) & 0xFF,
             (*blacklisted_ip >> 24) & 0xFF);
    fprintf(stdout,"Blacklisted IP: %s\n", ip);
    return 0;
} */

int main() {
    int fd;
    struct bpf_xdp_attach_opts *xdp_opts=malloc(sizeof(struct bpf_xdp_attach_opts));
    struct Test_Ringbuffer_bpf *skel;
    struct ring_buffer *rb = NULL;
//    struct ring_buffer *blacklist_rb = NULL;
    int buffer_fd;
    int err;

    skel = Test_Ringbuffer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }


    buffer_fd = bpf_map__fd(skel->maps.ringbuf);
    if (buffer_fd < 0) {
        fprintf(stderr, "Errore nell'ottenere il file descriptor del ring buffer.\n");
        return 1;
    }

    rb = ring_buffer__new(buffer_fd, handle_event, NULL, NULL);
    //blacklist_rb = ring_buffer__new(bpf_map__fd(skel->maps.blacklist_ringbuf), handle_blacklist, NULL, NULL);
    //   if (!rb || !blacklist_rb) {
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

	printf("Successfully started! Type ctrl+C for shutting down the module \n ");

    // Legge gli eventi finché il segnale non è ricevuto
    while (!stop) {
        int err = ring_buffer__poll(rb, -1);  // Timeout di 100 ms
        //ring_buffer__poll(blacklist_rb, -1);

/*         if (err < 0) {
            fprintf(stderr, "Errore durante il polling del ring buffer: %s\n", strerror(-err));
            break;
        } */
        fprintf(stderr, ".");
        sleep(1);
    }

    // Cleanup
    ring_buffer__free(rb);
    bpf_xdp_detach(INTERFACE, BPF_ANY,xdp_opts); 
    Test_Ringbuffer_bpf__destroy(skel);
    return 0;
}
