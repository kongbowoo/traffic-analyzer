#ifndef TRAFFIC_STATS_H
#define TRAFFIC_STATS_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include "../core/config.h"
#include "../protocol/tls.h"
#include "../protocol/dns.h"
#include "counters.h"

/* Traffic statistics */
struct traffic_stats {
    /* Basic statistics */
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;

    /* Application protocol statistics */
    uint64_t http_packets;
    uint64_t http_bytes;
    uint64_t https_packets;
    uint64_t https_bytes;
    uint64_t dns_packets;
    uint64_t dns_bytes;
    uint64_t icmp_bytes;

    /* DNS detailed statistics */
    uint64_t dns_queries;
    uint64_t dns_responses;
    uint64_t dns_a_queries;
    uint64_t dns_aaaa_queries;
    uint64_t dns_other_queries;

    /* TLS handshake statistics */
    uint64_t tls_client_hello;
    uint64_t tls_server_hello;
    uint64_t tls_v1_0;
    uint64_t tls_v1_1;
    uint64_t tls_v1_2;
    uint64_t tls_v1_3;
};

/* Statistics snapshot is defined in stats_collector.h */
struct stats_snapshot;

/* Initialize statistics */
void traffic_stats_init(struct traffic_stats *stats);

/* Reset statistics */
void traffic_stats_reset(struct traffic_stats *stats);

/* Calculate bandwidth in bps */
double calculate_bandwidth(uint64_t bytes, double time_delta_sec);

/* Update stats from packet info (simplified) */
void traffic_stats_update(struct traffic_stats *stats,
                         uint8_t ip_protocol,
                         uint8_t app_protocol,
                         uint32_t len);

/* Update TLS statistics */
void traffic_stats_update_tls(struct traffic_stats *stats, const struct tls_info *tls);

/* Update DNS statistics */
void traffic_stats_update_dns(struct traffic_stats *stats, const struct dns_info *dns);

/* Get protocol percentage */
double stats_get_protocol_percent(const struct traffic_stats *stats, uint8_t protocol);

/* Get application protocol percentage */
double stats_get_app_proto_percent(const struct traffic_stats *stats, uint8_t app_proto);

#endif /* TRAFFIC_STATS_H */