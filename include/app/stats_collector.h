#ifndef STATS_COLLECTOR_H
#define STATS_COLLECTOR_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include "../stats/traffic_stats.h"
#include "../analyzer/flow_table.h"
#include "../analyzer/ip_table.h"
#include "../analyzer/fingerprint_table.h"
#include "../analyzer/geolocation.h"
#include "packet_parser.h"

/* Statistics snapshot with top entries */
struct stats_snapshot {
    struct traffic_stats stats;
    struct flow_entry *top_flows[5];
    struct ip_entry *top_src_ips[5];
    struct ip_entry *top_dst_ips[5];
    struct fingerprint_entry *top_fingerprints[5];
    uint64_t bytes_last_period;
    double bandwidth;
    time_t timestamp;
};

/* Statistics collector */
struct stats_collector {
    struct traffic_stats stats;
    struct flow_table *flow_table;
    struct ip_table *src_ip_table;
    struct ip_table *dst_ip_table;
    struct fingerprint_table *fingerprint_table;
    struct geo_db *geo_db;
    struct stats_snapshot current;
    struct stats_snapshot previous;
    uint64_t total_bytes_start;
    bool geo_enabled;
};

/* Configuration for stats collector */
struct stats_config {
    uint32_t flow_table_size;
    uint32_t ip_table_size;
    uint32_t fingerprint_table_size;
    bool enable_geo;
};

/* Initialize stats collector */
struct stats_collector *stats_collector_init(const struct stats_config *config);

/* Destroy stats collector */
void stats_collector_destroy(struct stats_collector *collector);

/* Process a packet */
void stats_collector_process(struct stats_collector *collector,
                             const struct packet_info *info, uint32_t len);

/* Take snapshot of current statistics */
void stats_collector_snapshot(struct stats_collector *collector);

/* Get current snapshot */
const struct stats_snapshot *stats_collector_get_snapshot(
    const struct stats_collector *collector);

/* Get geolocation database (for display) */
struct geo_db *stats_collector_get_geo_db(struct stats_collector *collector);

/* Get protocol percentage */
double stats_collector_get_proto_percent(const struct stats_collector *collector,
                                         uint8_t protocol);

/* Get bandwidth */
double stats_collector_get_bandwidth(const struct stats_collector *collector);

#endif /* STATS_COLLECTOR_H */