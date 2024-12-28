#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "xdp_prog.skel.h"

void handle_event(void *ctx, void *data, size_t len) {
    struct packet_info *event = data;
    char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
             event->ip & 0xFF,
             (event->ip >> 8) & 0xFF,
             (event->ip >> 16) & 0xFF,
             (event->ip >> 24) & 0xFF);
    printf("Packet: IP=%s, Port=%u, Protocol=%s\n", ip, event->port, event->protocol);
}

void handle_blacklist(void *ctx, void *data, size_t len) {
    __u32 *blacklisted_ip = data;
    char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
             *blacklisted_ip & 0xFF,
             (*blacklisted_ip >> 8) & 0xFF,
             (*blacklisted_ip >> 16) & 0xFF,
             (*blacklisted_ip >> 24) & 0xFF);
    printf("Blacklisted IP: %s\n", ip);
}

int main() {
    struct xdp_prog *skel = xdp_prog__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }

    if (xdp_prog__attach(skel) < 0) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
    struct ring_buffer *blacklist_rb = ring_buffer__new(bpf_map__fd(skel->maps.blacklist_ringbuf), handle_blacklist, NULL, NULL);
    if (!rb || !blacklist_rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for packets and blacklist updates...\n");
    while (1) {
        ring_buffer__poll(rb, -1);
        ring_buffer__poll(blacklist_rb, -1);
    }

    xdp_prog__destroy(skel);
    return 0;
}
