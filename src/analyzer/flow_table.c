#include "flow_table.h"
#include <stdlib.h>
#include <string.h>

/* Initialize flow table */
struct flow_table *flow_table_init(uint32_t size)
{
    struct flow_table *table = calloc(1, sizeof(struct flow_table));
    if (!table) {
        return NULL;
    }

    table->entries = calloc(size, sizeof(struct flow_entry *));
    if (!table->entries) {
        free(table);
        return NULL;
    }

    table->size = size;
    table->count = 0;

    return table;
}

/* Destroy flow table */
void flow_table_destroy(struct flow_table *table)
{
    if (!table) {
        return;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct flow_entry *entry = table->entries[i];
        while (entry) {
            struct flow_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(table->entries);
    free(table);
}

/* Find or create flow entry */
struct flow_entry *flow_table_lookup(struct flow_table *table, const struct flow_key *key)
{
    if (!table || !key) {
        return NULL;
    }

    uint32_t idx = flow_key_hash(key, table->size);
    struct flow_entry *entry = table->entries[idx];

    while (entry) {
        if (flow_key_compare(key, &entry->key) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    /* Create new entry */
    entry = malloc(sizeof(struct flow_entry));
    if (!entry) {
        return NULL;
    }

    entry->key = *key;
    entry->packet_count = 0;
    entry->byte_count = 0;
    entry->next = table->entries[idx];
    table->entries[idx] = entry;
    table->count++;

    return entry;
}

/* Update flow statistics */
void flow_table_update(struct flow_entry *flow, uint32_t len)
{
    if (flow) {
        flow->packet_count++;
        flow->byte_count += len;
    }
}

/* Get top N flows by packet count */
void flow_table_get_top(struct flow_table *table, struct flow_entry **top, uint32_t n)
{
    if (!table || !top) {
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        top[i] = NULL;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct flow_entry *entry = table->entries[i];
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
uint32_t flow_table_count(const struct flow_table *table)
{
    return table ? table->count : 0;
}

uint32_t flow_table_size(const struct flow_table *table)
{
    return table ? table->size : 0;
}