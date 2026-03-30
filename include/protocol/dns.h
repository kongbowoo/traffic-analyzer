#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* DNS header */
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

/* DNS flags */
#define DNS_FLAG_QR    0x8000  /* Query/Response */
#define DNS_FLAG_OPCODE 0x7800 /* Operation code */
#define DNS_FLAG_AA    0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC    0x0200  /* Truncation */
#define DNS_FLAG_RD    0x0100  /* Recursion Desired */
#define DNS_FLAG_RA    0x0080  /* Recursion Available */
#define DNS_FLAG_Z     0x0040  /* Reserved */
#define DNS_FLAG_AD    0x0020  /* Authentic Data */
#define DNS_FLAG_CD    0x0010  /* Checking Disabled */
#define DNS_FLAG_RCODE 0x000F  /* Response Code */

/* DNS query types */
#define DNS_TYPE_A      1   /* IPv4 address */
#define DNS_TYPE_AAAA   28  /* IPv6 address */
#define DNS_TYPE_CNAME  5   /* Canonical name */
#define DNS_TYPE_MX     15  /* Mail exchange */
#define DNS_TYPE_TXT    16  /* Text */
#define DNS_TYPE_NS     2   /* Name server */
#define DNS_TYPE_PTR    12  /* Pointer */
#define DNS_TYPE_SOA    6   /* Start of authority */
#define DNS_TYPE_SRV    33  /* Service record */

/* Parsed DNS information */
struct dns_info {
    uint16_t id;
    uint16_t flags;
    uint16_t query_count;
    uint16_t answer_count;
    uint8_t  is_response;
    char domain[256];
    uint16_t qtype;
    bool valid;
};

/* Parse DNS packet */
int dns_parse(const uint8_t *packet, size_t len, struct dns_info *info);

/* Get DNS query type string */
const char *dns_qtype_to_str(uint16_t qtype);

/* Check if DNS packet is a response */
static inline bool dns_is_response(const struct dns_info *info)
{
    return info->is_response;
}

/* Get DNS RCODE */
static inline uint8_t dns_rcode(const struct dns_info *info)
{
    return info->flags & DNS_FLAG_RCODE;
}

#endif /* DNS_H */