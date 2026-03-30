#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "../core/hash_table.h"

/* Flow key (five-tuple) */
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

/* Flow entry */
struct flow_entry {
    struct flow_key key;
    uint64_t packet_count;
    uint64_t byte_count;
    struct flow_entry *next;
};

/* Flow table */
struct flow_table {
    struct flow_entry **entries;
    uint32_t size;
    uint32_t count;
};

/* Initialize flow table */
struct flow_table *flow_table_init(uint32_t size);

/* Destroy flow table */
void flow_table_destroy(struct flow_table *table);

/* Find or create flow entry */
struct flow_entry *flow_table_lookup(struct flow_table *table, const struct flow_key *key);

/* Update flow statistics */
void flow_table_update(struct flow_entry *flow, uint32_t len);

/* Get top N flows by packet count */
void flow_table_get_top(struct flow_table *table, struct flow_entry **top, uint32_t n);

/* Get table statistics */
uint32_t flow_table_count(const struct flow_table *table);
uint32_t flow_table_size(const struct flow_table *table);

/* Hash function for flow key */
static inline uint32_t flow_key_hash(const struct flow_key *key, uint32_t table_size)
{
    uint32_t hash = 5381;
    const uint8_t *p = (const uint8_t *)key;
    size_t len = sizeof(struct flow_key);

    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + p[i];
    }

    return hash % table_size;
}

/* Compare flow keys */
static inline int flow_key_compare(const struct flow_key *k1, const struct flow_key *k2)
{
    return memcmp(k1, k2, sizeof(struct flow_key));
}

#endif /* FLOW_TABLE_H */