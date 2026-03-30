#include "icmp.h"
#include <string.h>

/* Parse ICMP header */
int icmp_parse(const uint8_t *packet, size_t len, struct icmp_hdr *hdr)
{
    if (len < sizeof(struct icmp_hdr) || !hdr) {
        return -1;
    }

    memcpy(hdr, packet, sizeof(struct icmp_hdr));
    return 0;
}

/* Get ICMP type string */
const char *icmp_type_to_str(uint8_t type)
{
    switch (type) {
        case ICMP_ECHO_REPLY:
            return "Echo Reply";
        case ICMP_DEST_UNREACH:
            return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH:
            return "Source Quench";
        case ICMP_REDIRECT:
            return "Redirect";
        case ICMP_ECHO_REQUEST:
            return "Echo Request";
        case ICMP_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMP_PARAMETER_PROB:
            return "Parameter Problem";
        case ICMP_TIMESTAMP_REQ:
            return "Timestamp Request";
        case ICMP_TIMESTAMP_REP:
            return "Timestamp Reply";
        case ICMP_INFO_REQUEST:
            return "Information Request";
        case ICMP_INFO_REPLY:
            return "Information Reply";
        default:
            return "Unknown";
    }
}

/* Check if ICMP packet is valid */
bool icmp_is_valid(const struct icmp_hdr *hdr)
{
    if (!hdr) {
        return false;
    }

    /* Valid ICMP types are 0-40 */
    return hdr->type <= 40;
}