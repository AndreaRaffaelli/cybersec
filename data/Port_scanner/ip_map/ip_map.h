#ifndef IP_MAP_H
#define IP_MAP_H

#include <stddef.h>

#define MAX_IP_LENGTH 16          // Lunghezza massima di un indirizzo IP (xxx.xxx.xxx.xxx)
#define INITIAL_PORTS_CAPACITY 2  // Capacità massima delle porte per ciascun IP

// Struttura per la lista di porte con capacità fissa
typedef struct {
    int ports[INITIAL_PORTS_CAPACITY]; // Array fisso di porte
    size_t size;                       // Numero di porte attualmente utilizzate
} PortList;

// Struttura per una voce IP
typedef struct {
    char ip[MAX_IP_LENGTH]; // Indirizzo IP
    PortList portList;      // Lista di porte associate all'indirizzo IP
} IPEntry;

// Struttura per la mappa IP
typedef struct {
    IPEntry *entries; // Array dinamico di voci IP
    size_t size;      // Numero di voci attualmente utilizzate
    size_t capacity;  // Capacità attuale dell'array di voci IP
} IPMap;

// Funzioni per gestire la mappa IP
IPMap* init_ip_map();         // Inizializza la mappa IP
void destroy_ip_map(IPMap *map);  // Distrugge la mappa IP
int add_ip_entry(IPMap *map, const char *ip, int port); // Aggiunge un'entry alla mappa
void clear_ip_map(IPMap *map);    // Pulisce la mappa IP
void clear_ip_entry(IPMap *map, const char *ip); // Pulisce una singola entry della mappa
void print_ip_map(const IPMap *map); // Stampa la mappa IP

#endif // IP_MAP_H
