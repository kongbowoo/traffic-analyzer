#ifndef STATS_COLLECTOR_H
#define STATS_COLLECTOR_H

#include <stdint.h>
#include <time.h>
#include "flow_analyzer.h"
#include "packet_parser.h"

/* Statistics snapshot */
struct stats_snapshot {
    struct traffic_stats stats;
    struct flow_entry *top_flows[5];
    uint64_t bytes_last_period;
    double bandwidth;
    time_t timestamp;
};

/* Statistics collector */
struct stats_collector {
    struct traffic_stats stats;
    struct flow_table *flow_table;
    struct stats_snapshot current;
    struct stats_snapshot previous;
    uint64_t total_bytes_start;
};

/* Initialize statistics collector */
struct stats_collector *stats_collector_init(uint32_t flow_table_size);

/* Destroy statistics collector */
void stats_collector_destroy(struct stats_collector *collector);

/* Process a packet */
void stats_collector_process(struct stats_collector *collector,
                              const struct packet_info *info, uint32_t len);

/* Take a snapshot of current statistics */
void stats_collector_snapshot(struct stats_collector *collector);

/* Get protocol percentage */
double get_protocol_percent(struct stats_collector *collector, uint8_t protocol);

#endif /* STATS_COLLECTOR_H */