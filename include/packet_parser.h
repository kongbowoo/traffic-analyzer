#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <netinet/in.h>

/* Ethernet header */
struct eth_hdr {
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint16_t ether_type;
} __attribute__((packed));

/* IPv4 header */
struct ip_hdr {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

/* TCP header */
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

/* UDP header */
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

/* Flow key for five-tuple */
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

/* Parsed packet info */
struct packet_info {
    struct flow_key key;
    uint16_t ether_type;
    uint8_t  ip_version;
    uint8_t  ip_protocol;
    uint32_t total_len;
    uint8_t  valid;
};

/* Parse Ethernet header */
int parse_ethernet(const uint8_t *packet, uint32_t len, struct packet_info *info);

/* Parse IPv4 header */
int parse_ipv4(const uint8_t *packet, uint32_t len, struct packet_info *info);

/* Parse TCP header */
int parse_tcp(const uint8_t *packet, uint32_t len, struct packet_info *info);

/* Parse UDP header */
int parse_udp(const uint8_t *packet, uint32_t len, struct packet_info *info);

/* Parse full packet and extract five-tuple */
int parse_packet(const uint8_t *packet, uint32_t len, struct packet_info *info);

/* IP address to string conversion */
void ip_to_str(uint32_t ip, char *str, size_t len);

/* Protocol to string conversion */
const char *protocol_to_str(uint8_t protocol);

#endif /* PACKET_PARSER_H */