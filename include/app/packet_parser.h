#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef USE_DPDK
    #include <rte_mbuf.h>
#else
    /* Non-DPDK fallback */
    struct rte_mbuf {
        void *buf_addr;
        uint64_t buf_physaddr;
        uint16_t data_off;
        uint16_t refcnt;
        uint16_t nb_segs;
        uint16_t port;
        uint64_t ol_flags;
        uint32_t pkt_len;
        uint32_t data_len;
        /* ... truncated for non-DPDK mode */
    };
#endif

#include "analyzer/flow_table.h"
#include "protocol/tls.h"
#include "protocol/dns.h"

/* Parsed packet information */
struct packet_info {
    struct flow_key key;
    uint16_t ether_type;
    uint8_t  ip_version;
    uint8_t  ip_protocol;
    uint32_t total_len;
    bool valid;
    uint8_t  app_protocol;
    uint16_t dst_port;
    struct tls_info tls;
    struct dns_info dns;
};

/* Parse packet from DPDK mbuf */
#ifdef USE_DPDK
int packet_parse_mbuf(struct rte_mbuf *mbuf, struct packet_info *info);
#else
static inline int packet_parse_mbuf(void *mbuf, struct packet_info *info) {
    (void)mbuf; (void)info;
    return -1;
}
#endif

/* Parse packet from raw buffer */
int packet_parse_buffer(const uint8_t *packet, size_t len, struct packet_info *info);

/* Detect application protocol from packet content */
uint8_t packet_detect_app_protocol(const uint8_t *packet, size_t len,
                                   uint8_t ip_protocol, uint16_t dst_port);

/* Check if packet is valid */
static inline bool packet_is_valid(const struct packet_info *info)
{
    return info ? info->valid : false;
}

/* Get packet flow key */
static inline const struct flow_key *packet_flow_key(const struct packet_info *info)
{
    return info ? &info->key : NULL;
}

/* Get packet length */
static inline uint16_t packet_len(const struct packet_info *info)
{
    return info ? info->total_len : 0;
}

#endif /* PACKET_PARSER_H */