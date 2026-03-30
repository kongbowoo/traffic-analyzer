#include "stats_collector.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Initialize stats collector */
struct stats_collector *stats_collector_init(const struct stats_config *config)
{
    struct stats_collector *collector = calloc(1, sizeof(struct stats_collector));
    if (!collector) {
        return NULL;
    }

    /* Initialize flow table */
    collector->flow_table = flow_table_init(config->flow_table_size);
    if (!collector->flow_table) {
        free(collector);
        return NULL;
    }

    /* Initialize source IP table */
    collector->src_ip_table = ip_table_init(config->ip_table_size, IP_TYPE_SOURCE);
    if (!collector->src_ip_table) {
        flow_table_destroy(collector->flow_table);
        free(collector);
        return NULL;
    }

    /* Initialize destination IP table */
    collector->dst_ip_table = ip_table_init(config->ip_table_size, IP_TYPE_DESTINATION);
    if (!collector->dst_ip_table) {
        flow_table_destroy(collector->flow_table);
        ip_table_destroy(collector->src_ip_table);
        free(collector);
        return NULL;
    }

    /* Initialize fingerprint table */
    collector->fingerprint_table = fingerprint_table_init(config->fingerprint_table_size);
    if (!collector->fingerprint_table) {
        flow_table_destroy(collector->flow_table);
        ip_table_destroy(collector->src_ip_table);
        ip_table_destroy(collector->dst_ip_table);
        free(collector);
        return NULL;
    }

    /* Initialize geolocation database if enabled */
    collector->geo_enabled = config->enable_geo;
    if (collector->geo_enabled) {
        collector->geo_db = geo_db_init();
    }

    /* Initialize statistics */
    traffic_stats_init(&collector->stats);
    collector->current.timestamp = time(NULL);
    collector->previous.timestamp = time(NULL);

    return collector;
}

/* Destroy stats collector */
void stats_collector_destroy(struct stats_collector *collector)
{
    if (!collector) {
        return;
    }

    flow_table_destroy(collector->flow_table);
    ip_table_destroy(collector->src_ip_table);
    ip_table_destroy(collector->dst_ip_table);
    fingerprint_table_destroy(collector->fingerprint_table);

    if (collector->geo_db) {
        geo_db_destroy(collector->geo_db);
    }

    free(collector);
}

/* Process a packet */
void stats_collector_process(struct stats_collector *collector,
                             const struct packet_info *info, uint32_t len)
{
    if (!collector || !info || !info->valid) {
        return;
    }

    /* Update general statistics */
    traffic_stats_update(&collector->stats, info->ip_protocol, info->app_protocol, len);

    /* Update TLS statistics if applicable */
    if (info->app_protocol == APP_PROTO_HTTPS && info->tls.valid) {
        traffic_stats_update_tls(&collector->stats, &info->tls);
    }

    /* Update DNS statistics if applicable */
    if (info->app_protocol == APP_PROTO_DNS && info->dns.valid) {
        traffic_stats_update_dns(&collector->stats, &info->dns);
    }

    /* Update flow table if packet has a valid flow key */
    if (info->key.protocol == PROTOCOL_TCP || info->key.protocol == PROTOCOL_UDP) {
        struct flow_entry *flow = flow_table_lookup(collector->flow_table, &info->key);
        if (flow) {
            flow_table_update(flow, len);
        }

        /* Update source IP table */
        struct ip_entry *src_ip = ip_table_lookup(collector->src_ip_table, info->key.src_ip);
        if (src_ip) {
            ip_table_update(src_ip, len);
        }

        /* Update destination IP table */
        struct ip_entry *dst_ip = ip_table_lookup(collector->dst_ip_table, info->key.dst_ip);
        if (dst_ip) {
            ip_table_update(dst_ip, len);
        }

        /* Update fingerprint table for TLS ClientHello */
        if (info->app_protocol == APP_PROTO_HTTPS &&
            info->tls.valid &&
            info->tls.handshake_type == TLS_HS_CLIENT_HELLO &&
            strlen(info->tls.ja4_fingerprint) > 0) {
            struct fingerprint_entry *fp = fingerprint_table_lookup(
                collector->fingerprint_table, info->tls.ja4_fingerprint);
            if (fp) {
                fingerprint_table_update(fp);
            }
        }
    }
}

/* Take snapshot of current statistics */
void stats_collector_snapshot(struct stats_collector *collector)
{
    if (!collector) {
        return;
    }

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
    flow_table_get_top(collector->flow_table, collector->current.top_flows, 5);

    /* Get top source IPs */
    ip_table_get_top(collector->src_ip_table, collector->current.top_src_ips, 5);

    /* Get top destination IPs */
    ip_table_get_top(collector->dst_ip_table, collector->current.top_dst_ips, 5);

    /* Get top fingerprints */
    fingerprint_table_get_top(collector->fingerprint_table, collector->current.top_fingerprints, 5);
}

/* Get current snapshot */
const struct stats_snapshot *stats_collector_get_snapshot(
    const struct stats_collector *collector)
{
    return collector ? &collector->current : NULL;
}

/* Get geolocation database */
struct geo_db *stats_collector_get_geo_db(struct stats_collector *collector)
{
    return collector ? collector->geo_db : NULL;
}

/* Get protocol percentage */
double stats_collector_get_proto_percent(const struct stats_collector *collector,
                                         uint8_t protocol)
{
    if (!collector) {
        return 0.0;
    }
    return stats_get_protocol_percent(&collector->stats, protocol);
}

/* Get bandwidth */
double stats_collector_get_bandwidth(const struct stats_collector *collector)
{
    return collector ? collector->current.bandwidth : 0.0;
}