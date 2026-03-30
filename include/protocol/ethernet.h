#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "../core/types.h"

/* Non-DPDK fallback definitions */
#ifdef USE_DPDK
    #include <rte_ether.h>
    typedef struct rte_ether_hdr eth_hdr_t;
    typedef struct rte_ether_addr ether_addr_t;

    static inline uint16_t ether_get_type_raw(const eth_hdr_t *hdr) {
        return rte_be_to_cpu_16(hdr->ether_type);
    }
#else
    /* Non-DPDK definitions */
    struct ether_addr {
        uint8_t addr_bytes[6];
    } __attribute__((packed));
    typedef struct ether_addr ether_addr_t;

    struct eth_hdr {
        ether_addr_t dst_addr;
        ether_addr_t src_addr;
        uint16_t ether_type;
    } __attribute__((packed));
    typedef struct eth_hdr eth_hdr_t;

    #define ETHER_TYPE_IPv4  0x0800
    #define ETHER_TYPE_IPv6  0x86DD
    #define ETHER_TYPE_ARP   0x0806

    static inline uint16_t ether_get_type_raw(const eth_hdr_t *hdr) {
        return rte_be_to_cpu_16_compat(hdr->ether_type);
    }
#endif

/* Ethernet types - use DPDK definitions when available */
#ifndef ETHER_TYPE_IPv4
#define ETHER_TYPE_IPv4  RTE_ETHER_TYPE_IPV4
#endif
#ifndef ETHER_TYPE_IPv6
#define ETHER_TYPE_IPv6  RTE_ETHER_TYPE_IPV6
#endif
#ifndef ETHER_TYPE_ARP
#define ETHER_TYPE_ARP   RTE_ETHER_TYPE_ARP
#endif

/* Parse Ethernet header */
static inline int ethernet_parse(const uint8_t *packet, size_t len, eth_hdr_t *hdr)
{
    if (len < sizeof(eth_hdr_t) || !hdr) {
        return -1;
    }

    memcpy(hdr, packet, sizeof(eth_hdr_t));
    return 0;
}

/* Get Ethernet type as host byte order */
static inline uint16_t ether_get_type(const eth_hdr_t *hdr)
{
    return ether_get_type_raw(hdr);
}

/* Check if packet is IPv4 */
static inline bool ether_is_ipv4(const eth_hdr_t *hdr)
{
    return ether_get_type(hdr) == ETHER_TYPE_IPv4;
}

/* Check if packet is IPv6 */
static inline bool ether_is_ipv6(const eth_hdr_t *hdr)
{
    return ether_get_type(hdr) == ETHER_TYPE_IPv6;
}

/* Check if packet is ARP */
static inline bool ether_is_arp(const eth_hdr_t *hdr)
{
    return ether_get_type(hdr) == ETHER_TYPE_ARP;
}

/* Get Ethernet type string */
const char *ether_type_to_str(uint16_t ether_type);

/* Format MAC address to string */
void ether_addr_to_str(const ether_addr_t *addr, char *buf, size_t len);

#endif /* ETHERNET_H */