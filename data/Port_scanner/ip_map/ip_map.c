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

// Funzione per aggiungere un valore alla mappa
void add_ip_entry(IPMap *map, const char *ip, int port) {
    for (size_t i = 0; i < map->size; i++) {
        if (strcmp(map->entries[i].ip, ip) == 0) {
            if (map->entries[i].portList.size >= map->entries[i].portList.capacity) {
                map->entries[i].portList.capacity *= 2;
                map->entries[i].portList.ports = realloc(map->entries[i].portList.ports, map->entries[i].portList.capacity * sizeof(int));
            }
            map->entries[i].portList.ports[map->entries[i].portList.size++] = port;
            return;
        }
    }

    if (map->size >= map->capacity) {
        map->capacity *= 2;
        map->entries = realloc(map->entries, map->capacity * sizeof(IPEntry));
    }

    strcpy(map->entries[map->size].ip, ip);
    map->entries[map->size].portList.size = 0;
    map->entries[map->size].portList.capacity = INITIAL_PORTS_CAPACITY;
    map->entries[map->size].portList.ports = malloc(map->entries[map->size].portList.capacity * sizeof(int));
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
