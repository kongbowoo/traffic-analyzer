#include "packet_parser.h"
#include "../protocol/ethernet.h"
#include "../protocol/ip.h"
#include "../protocol/tcp.h"
#include "../protocol/udp.h"
#include "../protocol/tls.h"
#include "../protocol/dns.h"
#include "../core/config.h"
#include <string.h>
#include <arpa/inet.h>

/* Parse packet from DPDK mbuf */
#ifdef USE_DPDK
int packet_parse_mbuf(struct rte_mbuf *mbuf, struct packet_info *info)
{
    if (!mbuf || !info) {
        return -1;
    }

    uint16_t pkt_len = rte_pktmbuf_pkt_len(mbuf);
    uint8_t *packet_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

    return packet_parse_buffer(packet_data, pkt_len, info);
}
#endif

/* Parse packet from raw buffer */
int packet_parse_buffer(const uint8_t *packet, size_t len, struct packet_info *info)
{
    memset(info, 0, sizeof(struct packet_info));

    if (len < sizeof(eth_hdr_t)) {
        return -1;
    }

    /* Parse Ethernet header */
    const eth_hdr_t *eth = (const eth_hdr_t *)packet;
    info->ether_type = ether_get_type(eth);

    /* Only process IPv4 for now */
    if (info->ether_type != ETHER_TYPE_IPv4) {
        info->valid = false;
        return 0;
    }

    size_t ip_offset = sizeof(eth_hdr_t);
    if (len < ip_offset + sizeof(ip_hdr_t)) {
        return -1;
    }

    /* Parse IPv4 header */
    const ip_hdr_t *ip = (const ip_hdr_t *)(packet + ip_offset);

    info->ip_version = 4;
    info->ip_protocol = ip_protocol(ip);
    info->total_len = ip_total_len(ip);
    info->key.src_ip = ip_src_addr(ip);
    info->key.dst_ip = ip_dst_addr(ip);
    info->key.protocol = ip_protocol(ip);

    size_t ip_hdr_len_val = ip_hdr_len(ip);
    size_t l4_offset = ip_offset + ip_hdr_len_val;

    if (ip_protocol(ip) == IPPROTO_TCP) {
        if (len < l4_offset + sizeof(tcp_hdr_t)) {
            return -1;
        }

        const tcp_hdr_t *tcp = (const tcp_hdr_t *)(packet + l4_offset);

        info->key.src_port = tcp_src_port(tcp);
        info->key.dst_port = tcp_dst_port(tcp);
        info->dst_port = info->key.dst_port;

        /* Parse TLS if port 443 */
        if (info->key.dst_port == PORT_HTTPS || info->key.src_port == PORT_HTTPS) {
            size_t tcp_hdr_len_val = tcp_hdr_len(tcp);
            size_t payload_offset = l4_offset + tcp_hdr_len_val;
            size_t payload_len = len - payload_offset;
            if (payload_len > 0) {
                tls_record_parse(packet + payload_offset, payload_len, &info->tls);
            }
        }
    } else if (ip_protocol(ip) == IPPROTO_UDP) {
        if (len < l4_offset + sizeof(udp_hdr_t)) {
            return -1;
        }

        const udp_hdr_t *udp = (const udp_hdr_t *)(packet + l4_offset);

        info->key.src_port = udp_src_port(udp);
        info->key.dst_port = udp_dst_port(udp);
        info->dst_port = info->key.dst_port;

        /* Parse DNS if port 53 */
        if (info->key.dst_port == PORT_DNS || info->key.src_port == PORT_DNS) {
            size_t payload_offset = l4_offset + sizeof(udp_hdr_t);
            size_t payload_len = len - payload_offset;
            if (payload_len > 0) {
                dns_parse(packet + payload_offset, payload_len, &info->dns);
            }
        }
    } else if (ip_protocol(ip) == IPPROTO_ICMP) {
        /* ICMP packets don't have ports */
        info->app_protocol = APP_PROTO_ICMP;
    }

    /* Detect application protocol */
    info->app_protocol = packet_detect_app_protocol(packet, len, ip_protocol(ip), info->dst_port);

    info->valid = true;
    return 0;
}

/* Detect application protocol from packet content */
uint8_t packet_detect_app_protocol(const uint8_t *packet, size_t len,
                                   uint8_t ip_protocol, uint16_t dst_port)
{
    (void)packet; (void)len;  /* Unused in basic detection */

    if (ip_protocol == IPPROTO_TCP) {
        if (dst_port == PORT_HTTP || dst_port == PORT_HTTPS) {
            return dst_port == PORT_HTTPS ? APP_PROTO_HTTPS : APP_PROTO_HTTP;
        }
    } else if (ip_protocol == IPPROTO_UDP) {
        if (dst_port == PORT_DNS) {
            return APP_PROTO_DNS;
        }
    } else if (ip_protocol == IPPROTO_ICMP) {
        return APP_PROTO_ICMP;
    }

    return APP_PROTO_UNKNOWN;
}