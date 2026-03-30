#include "ip_table.h"
#include <stdlib.h>
#include <string.h>

/* Initialize IP table */
struct ip_table *ip_table_init(uint32_t size, ip_type_t type)
{
    struct ip_table *table = calloc(1, sizeof(struct ip_table));
    if (!table) {
        return NULL;
    }

    table->entries = calloc(size, sizeof(struct ip_entry *));
    if (!table->entries) {
        free(table);
        return NULL;
    }

    table->size = size;
    table->count = 0;
    table->type = type;

    return table;
}

/* Destroy IP table */
void ip_table_destroy(struct ip_table *table)
{
    if (!table) {
        return;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct ip_entry *entry = table->entries[i];
        while (entry) {
            struct ip_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(table->entries);
    free(table);
}

/* Find or create IP entry */
struct ip_entry *ip_table_lookup(struct ip_table *table, uint32_t ip)
{
    if (!table) {
        return NULL;
    }

    uint32_t idx = ip_hash(ip, table->size);
    struct ip_entry *entry = table->entries[idx];

    while (entry) {
        if (entry->ip == ip) {
            return entry;
        }
        entry = entry->next;
    }

    /* Create new entry */
    entry = malloc(sizeof(struct ip_entry));
    if (!entry) {
        return NULL;
    }

    entry->ip = ip;
    entry->packet_count = 0;
    entry->byte_count = 0;
    entry->next = table->entries[idx];
    table->entries[idx] = entry;
    table->count++;

    return entry;
}

/* Update IP statistics */
void ip_table_update(struct ip_entry *entry, uint32_t len)
{
    if (entry) {
        entry->packet_count++;
        entry->byte_count += len;
    }
}

/* Get top N IPs by packet count */
void ip_table_get_top(struct ip_table *table, struct ip_entry **top, uint32_t n)
{
    if (!table || !top) {
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        top[i] = NULL;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct ip_entry *entry = table->entries[i];
        while (entry) {
            uint32_t pos = 0;
            while (pos < n && top[pos] &&
                   entry->packet_count <= top[pos]->packet_count) {
                pos++;
            }

            if (pos < n) {
                for (uint32_t j = n - 1; j > pos; j--) {
                    top[j] = top[j - 1];
                }
                top[pos] = entry;
            }

            entry = entry->next;
        }
    }
}

/* Get table statistics */
uint32_t ip_table_count(const struct ip_table *table)
{
    return table ? table->count : 0;
}

uint32_t ip_table_size(const struct ip_table *table)
{
    return table ? table->size : 0;
}