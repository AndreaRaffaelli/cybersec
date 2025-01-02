#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ip_map.h"

// Funzione per inizializzare la mappa
IPMap* init_ip_map() {
    IPMap *map = malloc(sizeof(IPMap));
    map->size = 0;
    map->capacity = 10; // Capacità iniziale per la mappa IP
    map->entries = malloc(map->capacity * sizeof(IPEntry));
    return map;
}

// Funzione per distruggere la mappa
void destroy_ip_map(IPMap *map) {
    if (map) {
        free(map->entries); // La memoria per le voci IP è allocata dinamicamente
        free(map);          // La memoria per la mappa è allocata dinamicamente
    }
}

// Funzione per verificare se la porta è già presente nella lista
int is_port_present(const PortList *portList, int port) {
    for (size_t i = 0; i < portList->size; i++) {
        if (portList->ports[i] == port) {
            return 1; // La porta è già presente
        }
    }
    return 0; // La porta non è presente
}

int add_ip_entry(IPMap *map, const char *ip, int port) {
    for (size_t i = 0; i < map->size; i++) {
        if (strcmp(map->entries[i].ip, ip) == 0) {
            // Verifica se la porta è già presente
            if (is_port_present(&map->entries[i].portList, port)) {
                //printf("La porta %d e' gia' presente per l'IP %s.\n", port, ip);
                return 1;
            }

            if (map->entries[i].portList.size >= INITIAL_PORTS_CAPACITY) {
                // Se la capacità è piena, non aggiungiamo nuove porte -> ip verrà aggiunto a blacklist
                //fprintf(stderr, "Errore: la lista delle porte per l'IP %s e' piena\nRichiesta a %d droppata.\n\n", ip, port);
                return 2;
            }

            map->entries[i].portList.ports[map->entries[i].portList.size++] = port;
            return 0;
        }
    }

    if (map->size >= map->capacity) {
        IPEntry *new_entries = realloc(map->entries, map->capacity * 2 * sizeof(IPEntry));
        if (!new_entries) {
            //fprintf(stderr, "Errore durante il realloc della mappa IP\n");
            return -1;
        }
        map->entries = new_entries;
        map->capacity *= 2;
    }

    strncpy(map->entries[map->size].ip, ip, MAX_IP_LENGTH - 1);
    map->entries[map->size].ip[MAX_IP_LENGTH - 1] = '\0';

    // Inizializzazione della lista delle porte
    map->entries[map->size].portList.size = 0;

    // Aggiungiamo la porta solo se c'è spazio
    map->entries[map->size].portList.ports[map->entries[map->size].portList.size++] = port;
    map->size++;
    return 0;
}

// Funzione per pulire la mappa
void clear_ip_map(IPMap *map) {
    for (size_t i = 0; i < map->size; i++) {
        map->entries[i].portList.size = 0; // Resetta la lista delle porte
    }
}

void print_ip_map(const IPMap *map) {
    if (!map || map->size == 0) {
        //printf("La mappa IP è vuota.\n");
        return;
    }

    for (size_t i = 0; i < map->size; i++) {
        printf("IP: %s\n", map->entries[i].ip);
        printf("Porte: ");
        for (size_t j = 0; j < map->entries[i].portList.size; j++) {
            printf("%d\t", map->entries[i].portList.ports[j]);
        }
        printf("\n");
    }
}
