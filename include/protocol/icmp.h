#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ICMP header */
struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

/* ICMP types */
#define ICMP_ECHO_REPLY      0
#define ICMP_DEST_UNREACH    3
#define ICMP_SOURCE_QUENCH   4
#define ICMP_REDIRECT        5
#define ICMP_ECHO_REQUEST    8
#define ICMP_TIME_EXCEEDED   11
#define ICMP_PARAMETER_PROB  12
#define ICMP_TIMESTAMP_REQ   13
#define ICMP_TIMESTAMP_REP   14
#define ICMP_INFO_REQUEST    15
#define ICMP_INFO_REPLY      16

/* Parse ICMP header */
int icmp_parse(const uint8_t *packet, size_t len, struct icmp_hdr *hdr);

/* Get ICMP type string */
const char *icmp_type_to_str(uint8_t type);

/* Check if ICMP packet is valid */
bool icmp_is_valid(const struct icmp_hdr *hdr);

#endif /* ICMP_H */