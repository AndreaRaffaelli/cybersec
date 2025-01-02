#include <stdio.h>
#include "ip_map.h"

int main() {
    // Inizializzazione della mappa IP
    IPMap *map = init_ip_map();
    if (!map) {
        fprintf(stderr, "Errore durante l'inizializzazione della mappa IP\n");
        return 1;
    }

    printf("Mappa IP inizializzata con successo.\n");

    // Aggiunta di alcune entry alla mappa
    add_ip_entry(map, "192.168.0.1", 80);
    add_ip_entry(map, "192.168.0.1", 443);
    add_ip_entry(map, "192.168.0.2", 22);
    add_ip_entry(map, "192.168.0.3", 8080);
    add_ip_entry(map, "192.168.0.1", 80);
    add_ip_entry(map, "192.168.0.1", 81);
    add_ip_entry(map, "192.168.0.1", 82);
    add_ip_entry(map, "192.168.0.1", 83);


    printf("Entry aggiunte alla mappa IP.\n\n");

    // Stampa della mappa IP
    printf("Contenuto della mappa IP:\n");
    print_ip_map(map);

    // Test di pulizia di una entry
    printf("\nPulizia della mappa IP...\n");
    clear_ip_map(map);

    // Stampa della mappa dopo la pulizia
    printf("Contenuto della mappa IP dopo la pulizia:\n");
    print_ip_map(map);

    // Distruzione della mappa
    destroy_ip_map(map);
    printf("Mappa IP distrutta.\n");

    return 0;
}
