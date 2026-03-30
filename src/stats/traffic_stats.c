#include "traffic_stats.h"
#include <string.h>
#include <math.h>

/* Initialize statistics */
void traffic_stats_init(struct traffic_stats *stats)
{
    if (stats) {
        memset(stats, 0, sizeof(struct traffic_stats));
    }
}

/* Reset statistics */
void traffic_stats_reset(struct traffic_stats *stats)
{
    if (stats) {
        memset(stats, 0, sizeof(struct traffic_stats));
    }
}

/* Calculate bandwidth in bps */
double calculate_bandwidth(uint64_t bytes, double time_delta_sec)
{
    if (time_delta_sec <= 0.0) {
        return 0.0;
    }

    return (bytes * 8.0) / time_delta_sec;
}

/* Update stats from packet info */
void traffic_stats_update(struct traffic_stats *stats,
                         uint8_t ip_protocol,
                         uint8_t app_protocol,
                         uint32_t len)
{
    if (!stats) {
        return;
    }

    stats->total_packets++;
    stats->total_bytes += len;

    if (ip_protocol == PROTOCOL_TCP) {
        stats->tcp_packets++;
    } else if (ip_protocol == PROTOCOL_UDP) {
        stats->udp_packets++;
    } else if (ip_protocol == PROTOCOL_ICMP) {
        stats->icmp_packets++;
        stats->icmp_bytes += len;
    } else {
        stats->other_packets++;
    }

    if (app_protocol == APP_PROTO_HTTP) {
        stats->http_packets++;
        stats->http_bytes += len;
    } else if (app_protocol == APP_PROTO_HTTPS) {
        stats->https_packets++;
        stats->https_bytes += len;
    } else if (app_protocol == APP_PROTO_DNS) {
        stats->dns_packets++;
        stats->dns_bytes += len;
    }
}

/* Update TLS statistics */
void traffic_stats_update_tls(struct traffic_stats *stats, const struct tls_info *tls)
{
    if (!stats || !tls || !tls->valid) {
        return;
    }

    if (tls->handshake_type == TLS_HS_CLIENT_HELLO) {
        stats->tls_client_hello++;
    } else if (tls->handshake_type == TLS_HS_SERVER_HELLO) {
        stats->tls_server_hello++;
    }

    switch (tls->tls_version) {
        case TLS_VERSION_1_0:
            stats->tls_v1_0++;
            break;
        case TLS_VERSION_1_1:
            stats->tls_v1_1++;
            break;
        case TLS_VERSION_1_2:
            stats->tls_v1_2++;
            break;
        case TLS_VERSION_1_3:
            stats->tls_v1_3++;
            break;
    }
}

/* Update DNS statistics */
void traffic_stats_update_dns(struct traffic_stats *stats, const struct dns_info *dns)
{
    if (!stats || !dns || !dns->valid) {
        return;
    }

    if (dns->is_response) {
        stats->dns_responses++;
    } else {
        stats->dns_queries++;

        switch (dns->qtype) {
            case DNS_TYPE_A:
                stats->dns_a_queries++;
                break;
            case DNS_TYPE_AAAA:
                stats->dns_aaaa_queries++;
                break;
            default:
                stats->dns_other_queries++;
                break;
        }
    }
}

/* Get protocol percentage */
double stats_get_protocol_percent(const struct traffic_stats *stats, uint8_t protocol)
{
    if (!stats || stats->total_packets == 0) {
        return 0.0;
    }

    uint64_t count = 0;
    switch (protocol) {
        case PROTOCOL_TCP:
            count = stats->tcp_packets;
            break;
        case PROTOCOL_UDP:
            count = stats->udp_packets;
            break;
        case PROTOCOL_ICMP:
            count = stats->icmp_packets;
            break;
        default:
            return 0.0;
    }

    return (count * 100.0) / stats->total_packets;
}

/* Get application protocol percentage */
double stats_get_app_proto_percent(const struct traffic_stats *stats, uint8_t app_proto)
{
    if (!stats || stats->total_packets == 0) {
        return 0.0;
    }

    uint64_t count = 0;
    switch (app_proto) {
        case APP_PROTO_HTTP:
            count = stats->http_packets;
            break;
        case APP_PROTO_HTTPS:
            count = stats->https_packets;
            break;
        case APP_PROTO_DNS:
            count = stats->dns_packets;
            break;
        default:
            return 0.0;
    }

    return (count * 100.0) / stats->total_packets;
}