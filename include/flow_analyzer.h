#ifndef FLOW_ANALYZER_H
#define FLOW_ANALYZER_H

#include <stdint.h>
#include "packet_parser.h"

/* Flow table entry */
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

/* Statistics */
struct traffic_stats {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t other_packets;
};

/* Initialize flow table */
struct flow_table *flow_table_init(uint32_t size);

/* Destroy flow table */
void flow_table_destroy(struct flow_table *table);

/* Find or create flow entry */
struct flow_entry *flow_lookup(struct flow_table *table, const struct flow_key *key);

/* Update flow statistics */
void flow_update(struct flow_entry *flow, uint32_t len);

/* Initialize traffic statistics */
void stats_init(struct traffic_stats *stats);

/* Update traffic statistics */
void stats_update(struct traffic_stats *stats, const struct packet_info *info, uint32_t len);

/* Get top N flows by packet count */
void get_top_flows(struct flow_table *table, struct flow_entry **top_flows, uint32_t n);

/* Calculate bandwidth in bps based on time delta */
double calculate_bandwidth(uint64_t bytes, double time_delta_sec);

#endif /* FLOW_ANALYZER_H */