#include "dns.h"
#include <string.h>
#include <arpa/inet.h>

/* Parse DNS packet */
int dns_parse(const uint8_t *packet, size_t len, struct dns_info *info)
{
    memset(info, 0, sizeof(struct dns_info));

    if (len < sizeof(struct dns_hdr)) {
        return -1;
    }

    const struct dns_hdr *dns = (const struct dns_hdr *)packet;

    info->id = ntohs(dns->id);
    info->flags = ntohs(dns->flags);
    info->query_count = ntohs(dns->qdcount);
    info->answer_count = ntohs(dns->ancount);
    info->is_response = (info->flags & DNS_FLAG_QR) != 0;

    /* Parse the question section if available */
    if (info->query_count > 0 && len > sizeof(struct dns_hdr)) {
        const uint8_t *ptr = packet + sizeof(struct dns_hdr);
        int remaining = len - sizeof(struct dns_hdr);

        /* Parse domain name */
        int domain_len = 0;
        while (remaining > 0) {
            uint8_t label_len = *ptr;
            ptr++;
            remaining--;

            if (label_len == 0) {
                break;
            }

            /* Handle compressed names (pointer) */
            if (label_len >= 0xC0) {
                ptr++;
                remaining--;
                break;
            }

            /* Copy label */
            if (label_len <= remaining && domain_len < (int)sizeof(info->domain) - 2) {
                if (domain_len > 0) {
                    info->domain[domain_len++] = '.';
                }
                int copy_len = (int)label_len;
                if (domain_len + copy_len > (int)sizeof(info->domain) - 1) {
                    copy_len = (int)sizeof(info->domain) - 1 - domain_len;
                }
                memcpy(info->domain + domain_len, ptr, copy_len);
                domain_len += copy_len;
                ptr += label_len;
                remaining -= label_len;
            } else {
                break;
            }
        }

        /* Parse query type (QTYPE) */
        if (remaining >= 4) {
            info->qtype = ntohs(*(uint16_t *)ptr);
        }
    }

    info->valid = true;
    return 0;
}

/* Get DNS query type string */
const char *dns_qtype_to_str(uint16_t qtype)
{
    switch (qtype) {
        case DNS_TYPE_A:
            return "A";
        case DNS_TYPE_AAAA:
            return "AAAA";
        case DNS_TYPE_CNAME:
            return "CNAME";
        case DNS_TYPE_MX:
            return "MX";
        case DNS_TYPE_TXT:
            return "TXT";
        case DNS_TYPE_NS:
            return "NS";
        case DNS_TYPE_PTR:
            return "PTR";
        case DNS_TYPE_SOA:
            return "SOA";
        case DNS_TYPE_SRV:
            return "SRV";
        default:
            return "UNKNOWN";
    }
}