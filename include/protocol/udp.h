#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../core/types.h"

/* Non-DPDK fallback definitions */
#ifdef USE_DPDK
    #include <rte_udp.h>
    typedef struct rte_udp_hdr udp_hdr_t;
#else
    /* Non-DPDK definitions */
    struct udp_hdr {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t dgram_len;
        uint16_t dgram_cksum;
    } __attribute__((packed));
    typedef struct udp_hdr udp_hdr_t;
#endif

/* Parse UDP header */
static inline int udp_parse(const uint8_t *packet, size_t len, udp_hdr_t *hdr)
{
    if (len < sizeof(udp_hdr_t) || !hdr) {
        return -1;
    }

    memcpy(hdr, packet, sizeof(udp_hdr_t));
    return 0;
}

/* Get source port */
static inline uint16_t udp_src_port(const udp_hdr_t *hdr)
{
    return rte_be_to_cpu_16_compat(hdr->src_port);
}

/* Get destination port */
static inline uint16_t udp_dst_port(const udp_hdr_t *hdr)
{
    return rte_be_to_cpu_16_compat(hdr->dst_port);
}

/* Get UDP length */
static inline uint16_t udp_length(const udp_hdr_t *hdr)
{
    return rte_be_to_cpu_16_compat(hdr->dgram_len);
}

/* Get payload offset */
static inline size_t udp_payload_offset(const udp_hdr_t *hdr)
{
    (void)hdr;
    return sizeof(udp_hdr_t);
}

#endif /* UDP_H */