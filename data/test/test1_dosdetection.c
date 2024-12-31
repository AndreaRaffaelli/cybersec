#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>

#define DEST_IP "192.168.56.10" // Sostituisci con il tuo IP di destinazione
#define DEST_PORT 8080          // Sostituisci con la tua porta di destinazione

// Calcola il checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Calcola il tempo in microsecondi
unsigned long get_time_in_microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    char *source_ips[7] = {
        "192.168.56.1",
        "192.168.56.2",
        "192.168.56.3",
        "192.168.56.4",
        "192.168.56.5",
        "192.168.56.6",
        "192.168.56.10"
    };
    int packet_count[7] = {0}; // Contatori per ciascun IP sorgente
    int num_packets[7];        // Numero casuale di pacchetti per ciascun IP sorgente
    int total_packets = 0;     // Totale pacchetti da inviare

    // Genera un numero casuale di pacchetti per ciascun IP sorgente
    for (int i = 0; i < 7; i++) {
        num_packets[i] = rand() % 10 + 1; // Da 1 a 10 pacchetti per ogni IP
        total_packets += num_packets[i];
    }

    unsigned long start_time = get_time_in_microseconds();
    unsigned long end_time = start_time + 1000000; // Un secondo dopo

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    inet_pton(AF_INET, DEST_IP, &dest.sin_addr);

    for (int i = 0; i < 7; i++) {
        for (int j = 0; j < num_packets[i]; j++) {
            char packet[4096];
            memset(packet, 0, sizeof(packet));

            // Header IP
            struct iphdr *iph = (struct iphdr *)packet;
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

            char *source_ip = source_ips[i];

            // Costruzione header IP
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
            iph->id = htonl(rand() % 65535);
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_UDP;
            iph->saddr = inet_addr(source_ip);
            iph->daddr = dest.sin_addr.s_addr;
            iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

            // Costruzione header UDP
            udph->source = htons(rand() % 65535); // Porta sorgente casuale
            udph->dest = dest.sin_port;
            udph->len = htons(sizeof(struct udphdr));
            udph->check = 0; // Nessun checksum per semplificare

            // Invia il pacchetto
            if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                perror("Packet send failed");
            } else {
                printf("Packet sent from %s to %s:%d\n", source_ip, DEST_IP, DEST_PORT);
                packet_count[i]++; // Incrementa il contatore per l'IP sorgente
            }

            // Calcola il tempo rimanente
            unsigned long current_time = get_time_in_microseconds();
            unsigned long time_left = end_time - current_time;
            if (total_packets > 0 && time_left > 0) {
                usleep(time_left / total_packets); // Dividi il tempo rimanente equamente
            }
        }
    }

    close(sock);

    // Stampa il conteggio dei pacchetti per ciascun IP sorgente
    printf("\nPacket count by source IP:\n");
    for (int i = 0; i < 7; i++) {
        printf("%s: %d packets\n", source_ips[i], packet_count[i]);
    }

    return 0;
}
