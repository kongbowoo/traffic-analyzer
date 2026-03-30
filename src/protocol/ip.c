#include "ip.h"
#include <arpa/inet.h>
#include <stdio.h>

/* Format IP address to string */
void ip_addr_to_str(uint32_t ip, char *buf, size_t len)
{
    if (!buf || len < 16) {
        return;
    }

    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(buf, len, "%s", inet_ntoa(addr));
}