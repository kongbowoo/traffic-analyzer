#include "fingerprint_table.h"
#include <stdlib.h>
#include <string.h>

/* Initialize fingerprint table */
struct fingerprint_table *fingerprint_table_init(uint32_t size)
{
    struct fingerprint_table *table = calloc(1, sizeof(struct fingerprint_table));
    if (!table) {
        return NULL;
    }

    table->entries = calloc(size, sizeof(struct fingerprint_entry *));
    if (!table->entries) {
        free(table);
        return NULL;
    }

    table->size = size;
    table->count = 0;

    return table;
}

/* Destroy fingerprint table */
void fingerprint_table_destroy(struct fingerprint_table *table)
{
    if (!table) {
        return;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct fingerprint_entry *entry = table->entries[i];
        while (entry) {
            struct fingerprint_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(table->entries);
    free(table);
}

/* Find or create fingerprint entry */
struct fingerprint_entry *fingerprint_table_lookup(struct fingerprint_table *table,
                                                   const char *fingerprint)
{
    if (!table || !fingerprint) {
        return NULL;
    }

    uint32_t idx = fingerprint_hash(fingerprint, table->size);
    struct fingerprint_entry *entry = table->entries[idx];

    while (entry) {
        if (strcmp(entry->fingerprint, fingerprint) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    /* Create new entry */
    entry = malloc(sizeof(struct fingerprint_entry));
    if (!entry) {
        return NULL;
    }

    strncpy(entry->fingerprint, fingerprint, sizeof(entry->fingerprint) - 1);
    entry->fingerprint[sizeof(entry->fingerprint) - 1] = '\0';
    entry->packet_count = 0;
    entry->next = table->entries[idx];
    table->entries[idx] = entry;
    table->count++;

    return entry;
}

/* Update fingerprint statistics */
void fingerprint_table_update(struct fingerprint_entry *entry)
{
    if (entry) {
        entry->packet_count++;
    }
}

/* Get top N fingerprints by packet count */
void fingerprint_table_get_top(struct fingerprint_table *table,
                                struct fingerprint_entry **top,
                                uint32_t n)
{
    if (!table || !top) {
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        top[i] = NULL;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct fingerprint_entry *entry = table->entries[i];
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
uint32_t fingerprint_table_count(const struct fingerprint_table *table)
{
    return table ? table->count : 0;
}

uint32_t fingerprint_table_size(const struct fingerprint_table *table)
{
    return table ? table->size : 0;
}