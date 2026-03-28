#include "flow_analyzer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Simple hash function for flow key */
static uint32_t flow_hash(const struct flow_key *key, uint32_t size)
{
    uint32_t hash = 5381;
    uint8_t *p = (uint8_t *)key;
    size_t len = sizeof(struct flow_key);

    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + p[i];
    }

    return hash % size;
}

/* Compare flow keys */
static int flow_key_compare(const struct flow_key *k1, const struct flow_key *k2)
{
    return memcmp(k1, k2, sizeof(struct flow_key));
}

/* Initialize flow table */
struct flow_table *flow_table_init(uint32_t size)
{
    struct flow_table *table = malloc(sizeof(struct flow_table));
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
struct flow_entry *flow_lookup(struct flow_table *table, const struct flow_key *key)
{
    uint32_t idx = flow_hash(key, table->size);
    struct flow_entry *entry = table->entries[idx];

    /* Search for existing entry */
    while (entry) {
        if (flow_key_compare(&entry->key, key) == 0) {
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
void flow_update(struct flow_entry *flow, uint32_t len)
{
    flow->packet_count++;
    flow->byte_count += len;
}

/* Initialize traffic statistics */
void stats_init(struct traffic_stats *stats)
{
    memset(stats, 0, sizeof(struct traffic_stats));
}

/* Update traffic statistics */
void stats_update(struct traffic_stats *stats, const struct packet_info *info, uint32_t len)
{
    stats->total_packets++;
    stats->total_bytes += len;

    if (info->ip_version == 4) {
        stats->ipv4_packets++;
    } else if (info->ip_version == 6) {
        stats->ipv6_packets++;
    }

    if (info->ip_protocol == 6) {  /* TCP */
        stats->tcp_packets++;
    } else if (info->ip_protocol == 17) {  /* UDP */
        stats->udp_packets++;
    } else {
        stats->other_packets++;
    }
}

/* Get top N flows by packet count */
void get_top_flows(struct flow_table *table, struct flow_entry **top_flows, uint32_t n)
{
    /* Initialize top flows array */
    for (uint32_t i = 0; i < n; i++) {
        top_flows[i] = NULL;
    }

    /* Iterate through all entries */
    for (uint32_t i = 0; i < table->size; i++) {
        struct flow_entry *entry = table->entries[i];
        while (entry) {
            /* Find position in top flows */
            uint32_t pos = 0;
            while (pos < n && top_flows[pos] &&
                   entry->packet_count <= top_flows[pos]->packet_count) {
                pos++;
            }

            if (pos < n) {
                /* Shift entries down */
                for (uint32_t j = n - 1; j > pos; j--) {
                    top_flows[j] = top_flows[j - 1];
                }
                top_flows[pos] = entry;
            }

            entry = entry->next;
        }
    }
}

/* Calculate bandwidth in bps based on time delta */
double calculate_bandwidth(uint64_t bytes, double time_delta_sec)
{
    if (time_delta_sec <= 0.0) {
        return 0.0;
    }

    return (bytes * 8.0) / time_delta_sec;
}