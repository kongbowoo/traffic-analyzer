#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "../core/types.h"

/* Non-DPDK fallback definitions */
#ifdef USE_DPDK
    #include <rte_tcp.h>
    typedef struct rte_tcp_hdr tcp_hdr_t;

    #define TCP_FLAG_FIN  RTE_TCP_FIN_FLAG
    #define TCP_FLAG_SYN  RTE_TCP_SYN_FLAG
    #define TCP_FLAG_RST  RTE_TCP_RST_FLAG
    #define TCP_FLAG_PSH  RTE_TCP_PSH_FLAG
    #define TCP_FLAG_ACK  RTE_TCP_ACK_FLAG
    #define TCP_FLAG_URG  RTE_TCP_URG_FLAG
#else
    /* Non-DPDK definitions */
    struct tcp_hdr {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t sent_seq;
        uint32_t recv_ack;
        uint8_t  data_off;      /* Data offset (4 bits) + Reserved (4 bits) */
        uint8_t  tcp_flags;     /* Flags */
        uint16_t rx_win;
        uint16_t cksum;
        uint16_t tcp_urp;
    } __attribute__((packed));
    typedef struct tcp_hdr tcp_hdr_t;

    #define TCP_FLAG_FIN  0x01
    #define TCP_FLAG_SYN  0x02
    #define TCP_FLAG_RST  0x04
    #define TCP_FLAG_PSH  0x08
    #define TCP_FLAG_ACK  0x10
    #define TCP_FLAG_URG  0x20
#endif

/* Parse TCP header */
static inline int tcp_parse(const uint8_t *packet, size_t len, tcp_hdr_t *hdr)
{
    if (len < sizeof(tcp_hdr_t) || !hdr) {
        return -1;
    }

    memcpy(hdr, packet, sizeof(tcp_hdr_t));
    return 0;
}

/* Get source port */
static inline uint16_t tcp_src_port(const tcp_hdr_t *hdr)
{
    return rte_be_to_cpu_16_compat(hdr->src_port);
}

/* Get destination port */
static inline uint16_t tcp_dst_port(const tcp_hdr_t *hdr)
{
    return rte_be_to_cpu_16_compat(hdr->dst_port);
}

/* Get TCP header length (including options) */
static inline uint8_t tcp_hdr_len(const tcp_hdr_t *hdr)
{
    return (hdr->data_off >> 4) * 4;
}

/* Get payload offset */
static inline size_t tcp_payload_offset(const tcp_hdr_t *hdr)
{
    return tcp_hdr_len(hdr);
}

/* Check if packet is SYN */
static inline bool tcp_is_syn(const tcp_hdr_t *hdr)
{
    return (hdr->tcp_flags & TCP_FLAG_SYN) != 0;
}

/* Check if packet is FIN */
static inline bool tcp_is_fin(const tcp_hdr_t *hdr)
{
    return (hdr->tcp_flags & TCP_FLAG_FIN) != 0;
}

/* Check if packet is RST */
static inline bool tcp_is_rst(const tcp_hdr_t *hdr)
{
    return (hdr->tcp_flags & TCP_FLAG_RST) != 0;
}

/* Check if packet has ACK */
static inline bool tcp_is_ack(const tcp_hdr_t *hdr)
{
    return (hdr->tcp_flags & TCP_FLAG_ACK) != 0;
}

/* Get sequence number */
static inline uint32_t tcp_seq_num(const tcp_hdr_t *hdr)
{
    return rte_be_to_cpu_32_compat(hdr->sent_seq);
}

/* Get acknowledgment number */
static inline uint32_t tcp_ack_num(const tcp_hdr_t *hdr)
{
    return rte_be_to_cpu_32_compat(hdr->recv_ack);
}

#endif /* TCP_H */