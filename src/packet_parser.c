#include "packet_parser.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHER_TYPE_IPv4  0x0800
#define ETHER_TYPE_IPv6  0x86DD
#define ETHER_TYPE_ARP   0x0806

#define IP_PROTOCOL_TCP  6
#define IP_PROTOCOL_UDP  17

/* Parse Ethernet header */
int parse_ethernet(const uint8_t *packet, uint32_t len, struct packet_info *info)
{
    if (len < sizeof(struct eth_hdr)) {
        return -1;
    }

    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    info->ether_type = ntohs(eth->ether_type);

    return 0;
}

/* Parse IPv4 header */
int parse_ipv4(const uint8_t *packet, uint32_t len, struct packet_info *info)
{
    if (len < sizeof(struct eth_hdr) + sizeof(struct ip_hdr)) {
        return -1;
    }

    const struct ip_hdr *ip = (const struct ip_hdr *)(packet + sizeof(struct eth_hdr));
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    if (len < sizeof(struct eth_hdr) + ihl) {
        return -1;
    }

    info->ip_version = 4;
    info->ip_protocol = ip->protocol;
    info->total_len = ntohs(ip->total_length);
    info->key.src_ip = ip->src_ip;
    info->key.dst_ip = ip->dst_ip;
    info->key.protocol = ip->protocol;

    return ihl;
}

/* Parse TCP header */
int parse_tcp(const uint8_t *packet, uint32_t len, struct packet_info *info)
{
    const struct ip_hdr *ip = (const struct ip_hdr *)(packet + sizeof(struct eth_hdr));
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    uint32_t ip_payload_offset = sizeof(struct eth_hdr) + ihl;
    if (len < ip_payload_offset + sizeof(struct tcp_hdr)) {
        return -1;
    }

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(packet + ip_payload_offset);
    info->key.src_port = ntohs(tcp->src_port);
    info->key.dst_port = ntohs(tcp->dst_port);

    return 0;
}

/* Parse UDP header */
int parse_udp(const uint8_t *packet, uint32_t len, struct packet_info *info)
{
    const struct ip_hdr *ip = (const struct ip_hdr *)(packet + sizeof(struct eth_hdr));
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;

    uint32_t ip_payload_offset = sizeof(struct eth_hdr) + ihl;
    if (len < ip_payload_offset + sizeof(struct udp_hdr)) {
        return -1;
    }

    const struct udp_hdr *udp = (const struct udp_hdr *)(packet + ip_payload_offset);
    info->key.src_port = ntohs(udp->src_port);
    info->key.dst_port = ntohs(udp->dst_port);

    return 0;
}

/* Parse full packet and extract five-tuple */
int parse_packet(const uint8_t *packet, uint32_t len, struct packet_info *info)
{
    memset(info, 0, sizeof(struct packet_info));

    /* Parse Ethernet header */
    if (parse_ethernet(packet, len, info) < 0) {
        return -1;
    }

    /* Only process IPv4 packets for now */
    if (info->ether_type != ETHER_TYPE_IPv4) {
        info->valid = 0;
        return 0;
    }

    /* Parse IPv4 header */
    if (parse_ipv4(packet, len, info) < 0) {
        return -1;
    }

    /* Parse transport layer header */
    if (info->key.protocol == IP_PROTOCOL_TCP) {
        if (parse_tcp(packet, len, info) < 0) {
            return -1;
        }
    } else if (info->key.protocol == IP_PROTOCOL_UDP) {
        if (parse_udp(packet, len, info) < 0) {
            return -1;
        }
    }

    info->valid = 1;
    return 0;
}

/* IP address to string conversion */
void ip_to_str(uint32_t ip, char *str, size_t len)
{
    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(str, len, "%s", inet_ntoa(addr));
}

/* Protocol to string conversion */
const char *protocol_to_str(uint8_t protocol)
{
    switch (protocol) {
        case IP_PROTOCOL_TCP:
            return "TCP";
        case IP_PROTOCOL_UDP:
            return "UDP";
        case 1:
            return "ICMP";
        case 2:
            return "IGMP";
        default:
            return "OTHER";
    }
}