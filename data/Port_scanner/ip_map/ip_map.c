#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ip_map.h"

// Funzione per inizializzare la mappa
IPMap* init_ip_map() {
    IPMap *map = malloc(sizeof(IPMap));
    map->size = 0;
    map->capacity = 10; // Capacità iniziale
    map->entries = malloc(map->capacity * sizeof(IPEntry));
    return map;
}

// Funzione per distruggere la mappa
void destroy_ip_map(IPMap *map) {
    if (map) {
        for (size_t i = 0; i < map->size; i++) {
            free(map->entries[i].portList.ports);
        }
        free(map->entries);
        free(map);
    }
}

void add_ip_entry(IPMap *map, const char *ip, int port) {
    for (size_t i = 0; i < map->size; i++) {
        if (strcmp(map->entries[i].ip, ip) == 0) {
            if (map->entries[i].portList.size >= map->entries[i].portList.capacity) {
                int *new_ports = realloc(map->entries[i].portList.ports, map->entries[i].portList.capacity * 2 * sizeof(int));
                if (!new_ports) {
                    fprintf(stderr, "Errore durante il realloc della lista di porte per IP %s\n", ip);
                    return;
                }
                map->entries[i].portList.ports = new_ports;
                map->entries[i].portList.capacity *= 2;
            }
            map->entries[i].portList.ports[map->entries[i].portList.size++] = port;
            return;
        }
    }

    if (map->size >= map->capacity) {
        IPEntry *new_entries = realloc(map->entries, map->capacity * 2 * sizeof(IPEntry));
        if (!new_entries) {
            fprintf(stderr, "Errore durante il realloc della mappa IP\n");
            return;
        }
        map->entries = new_entries;
        map->capacity *= 2;
    }

    strncpy(map->entries[map->size].ip, ip, MAX_IP_LENGTH - 1);
    map->entries[map->size].ip[MAX_IP_LENGTH - 1] = '\0';

    map->entries[map->size].portList.size = 0;
    map->entries[map->size].portList.capacity = INITIAL_PORTS_CAPACITY;
    map->entries[map->size].portList.ports = malloc(map->entries[map->size].portList.capacity * sizeof(int));
    if (!map->entries[map->size].portList.ports) {
        fprintf(stderr, "Errore di allocazione memoria per le porte dell'IP %s\n", ip);
        return;
    }
    map->entries[map->size].portList.ports[map->entries[map->size].portList.size++] = port;
    map->size++;
}

// Funzione per pulire la mappa
void clear_ip_map(IPMap *map) {
    for (size_t i = 0; i < map->size; i++) {
        map->entries[i].portList.size = 0; // Resetta la lista delle porte
    }
}

// Funzione per pulire
