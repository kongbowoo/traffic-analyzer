#include "stats_collector.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Initialize statistics collector */
struct stats_collector *stats_collector_init(uint32_t flow_table_size)
{
    struct stats_collector *collector = malloc(sizeof(struct stats_collector));
    if (!collector) {
        return NULL;
    }

    memset(collector, 0, sizeof(struct stats_collector));

    collector->flow_table = flow_table_init(flow_table_size);
    if (!collector->flow_table) {
        free(collector);
        return NULL;
    }

    stats_init(&collector->stats);
    collector->current.timestamp = time(NULL);
    collector->previous.timestamp = time(NULL);

    return collector;
}

/* Destroy statistics collector */
void stats_collector_destroy(struct stats_collector *collector)
{
    if (!collector) {
        return;
    }

    flow_table_destroy(collector->flow_table);
    free(collector);
}

/* Process a packet */
void stats_collector_process(struct stats_collector *collector,
                              const struct packet_info *info, uint32_t len)
{
    /* Update general statistics */
    stats_update(&collector->stats, info, len);

    /* Update flow table if packet is valid and has a flow key */
    if (info->valid && (info->key.protocol == 6 || info->key.protocol == 17)) {
        struct flow_entry *flow = flow_lookup(collector->flow_table, &info->key);
        if (flow) {
            flow_update(flow, len);
        }
    }
}

/* Take a snapshot of current statistics */
void stats_collector_snapshot(struct stats_collector *collector)
{
    /* Store previous snapshot */
    memcpy(&collector->previous, &collector->current, sizeof(struct stats_snapshot));

    /* Create new snapshot */
    memcpy(&collector->current.stats, &collector->stats, sizeof(struct traffic_stats));
    collector->current.timestamp = time(NULL);

    /* Calculate bandwidth */
    double time_delta = difftime(collector->current.timestamp,
                                  collector->previous.timestamp);
    if (time_delta > 0) {
        collector->current.bytes_last_period = collector->current.stats.total_bytes -
                                               collector->previous.stats.total_bytes;
        collector->current.bandwidth = calculate_bandwidth(collector->current.bytes_last_period,
                                                           time_delta);
    } else {
        collector->current.bandwidth = 0.0;
    }

    /* Get top flows */
    get_top_flows(collector->flow_table, collector->current.top_flows, 5);
}

/* Get protocol percentage */
double get_protocol_percent(struct stats_collector *collector, uint8_t protocol)
{
    if (collector->stats.total_packets == 0) {
        return 0.0;
    }

    uint64_t count = 0;
    switch (protocol) {
        case 10: /* IPv4 (custom enum value) */
            count = collector->stats.ipv4_packets;
            break;
        case 11: /* IPv6 (custom enum value) */
            count = collector->stats.ipv6_packets;
            break;
        case 6:  /* TCP */
            count = collector->stats.tcp_packets;
            break;
        case 17: /* UDP */
            count = collector->stats.udp_packets;
            break;
        default:
            return 0.0;
    }

    return (count * 100.0) / collector->stats.total_packets;
}