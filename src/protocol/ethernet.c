#include "ethernet.h"
#include <string.h>
#include <stdio.h>

/* Format MAC address to string - inline function implementation */
void ether_addr_to_bytes(const uint8_t *addr, char *buf, size_t len)
{
    if (!addr || !buf || len < 18) {
        return;
    }

    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/* Get Ethernet type string */
const char *ether_type_to_str(uint16_t ether_type)
{
    switch (ether_type) {
        case ETHER_TYPE_IPv4:
            return "IPv4";
        case ETHER_TYPE_IPv6:
            return "IPv6";
        case ETHER_TYPE_ARP:
            return "ARP";
        default:
            return "Unknown";
    }
}

/* Format MAC address to string */
void ether_addr_to_str(const ether_addr_t *addr, char *buf, size_t len)
{
    if (!addr || !buf || len < 18) {
        return;
    }

#ifdef USE_DPDK
    rte_ether_format_addr(buf, len, (const struct rte_ether_addr *)addr);
#else
    ether_addr_to_bytes(addr->addr_bytes, buf, len);
#endif
}