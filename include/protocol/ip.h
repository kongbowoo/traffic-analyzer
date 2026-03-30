#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <string.h>
#include "../core/types.h"

/* Non-DPDK fallback definitions */
#ifdef USE_DPDK
    #include <rte_ip.h>
    typedef struct rte_ipv4_hdr ip_hdr_t;
#else
    /* Non-DPDK definitions */
    struct ip_hdr {
        uint8_t  version_ihl;    /* Version (4 bits) + IHL (4 bits) */
        uint8_t  type_of_service;
        uint16_t total_length;
        uint16_t packet_id;
        uint16_t fragment_offset;
        uint8_t  time_to_live;
        uint8_t  next_proto_id;   /* Protocol */
        uint16_t hdr_checksum;
        uint32_t src_addr;
        uint32_t dst_addr;
    } __attribute__((packed));
    typedef struct ip_hdr ip_hdr_t;
#endif

/* IPv4 protocol numbers */
#ifndef IP_PROTOCOL_ICMP
#define IP_PROTOCOL_ICMP  IPPROTO_ICMP
#endif
#ifndef IP_PROTOCOL_TCP
#define IP_PROTOCOL_TCP   IPPROTO_TCP
#endif
#ifndef IP_PROTOCOL_UDP
#define IP_PROTOCOL_UDP   IPPROTO_UDP
#endif

/* Get IP header length from version_ihl field */
static inline uint8_t ip_hdr_len(const ip_hdr_t *hdr)
{
    return (hdr->version_ihl & 0x0F) * 4;
}

/* Parse IPv4 header, returns IP header length (including IHL) */
static inline int ip_parse(const uint8_t *packet, size_t len, ip_hdr_t *hdr)
{
    if (len < sizeof(ip_hdr_t) || !hdr) {
        return -1;
    }

    memcpy(hdr, packet, sizeof(ip_hdr_t));
    return (int)ip_hdr_len(hdr);
}

/* Get total length */
static inline uint16_t ip_total_len(const ip_hdr_t *hdr)
{
    return rte_be_to_cpu_16_compat(hdr->total_length);
}

/* Get source IP */
static inline uint32_t ip_src_addr(const ip_hdr_t *hdr)
{
    return hdr->src_addr;
}

/* Get destination IP */
static inline uint32_t ip_dst_addr(const ip_hdr_t *hdr)
{
    return hdr->dst_addr;
}

/* Get protocol */
static inline uint8_t ip_protocol(const ip_hdr_t *hdr)
{
    return hdr->next_proto_id;
}

/* Check if packet is IPv4 */
static inline bool is_ipv4(const uint8_t *packet)
{
    return (packet[0] & 0xF0) == 0x40;
}

/* Format IP address to string */
void ip_addr_to_str(uint32_t ip, char *buf, size_t len);

/* Convert IP address to host byte order */
static inline uint32_t ip_to_host(uint32_t ip)
{
    return rte_be_to_cpu_32_compat(ip);
}

/* Convert IP address to network byte order */
static inline uint32_t ip_to_network(uint32_t ip)
{
    return rte_cpu_to_be_32_compat(ip);
}

#endif /* IP_H */