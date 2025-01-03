#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 84
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    // Creazione del socket UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Impostazione dell'indirizzo del server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // Accetta connessioni da qualsiasi indirizzo
    server_addr.sin_port = htons(PORT); // Porta 8080

    // Binding del socket
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server in ascolto sulla porta %d...\n", PORT);
int num = 0;
    while (1) {
        // Ricezione dei dati
        ssize_t n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, MSG_WAITALL,
                             (struct sockaddr *)&client_addr, &addr_len);
        buffer[n] = '\0'; // Aggiungi il terminatore di stringa

        // Stampa i dati ricevuti e l'indirizzo del client
        num++;
        printf("Ricevuto: %s\n", buffer);
        printf("Da: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        printf("NUMERO PACCHETTI RICEVUTI: %d\n", num);
    }
    // Chiusura del socket
    close(sockfd);
    return 0;
}
