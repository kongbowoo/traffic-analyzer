#include "formatter.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* Format IP address to string */
void format_ip(uint32_t ip, char *buf, size_t len)
{
    if (!buf || len < 16) {
        return;
    }

    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(buf, len, "%s", inet_ntoa(addr));
}

/* Format bytes to human readable string */
void format_bytes(uint64_t bytes, char *buf, size_t len)
{
    if (!buf || len < 32) {
        return;
    }

    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_idx = 0;
    double value = bytes;

    while (value >= 1024.0 && unit_idx < 4) {
        value /= 1024.0;
        unit_idx++;
    }

    snprintf(buf, len, "%.2f %s", value, units[unit_idx]);
}

/* Format bandwidth to human readable string */
void format_bandwidth(double bps, char *buf, size_t len)
{
    if (!buf || len < 32) {
        return;
    }

    const char *units[] = {"bps", "Kbps", "Mbps", "Gbps"};
    int unit_idx = 0;
    double value = bps;

    while (value >= 1000.0 && unit_idx < 3) {
        value /= 1000.0;
        unit_idx++;
    }

    snprintf(buf, len, "%.2f %s", value, units[unit_idx]);
}

/* Format MAC address to string */
void format_mac(const uint8_t *mac, char *buf, size_t len)
{
    if (!mac || !buf || len < 18) {
        return;
    }

    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Format timestamp to string */
void format_timestamp(time_t t, char *buf, size_t len)
{
    if (!buf || len < 32) {
        return;
    }

    struct tm *tm = localtime(&t);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm);
}

/* Format integer with thousands separator */
void format_number(uint64_t num, char *buf, size_t len)
{
    if (!buf || len < 32) {
        return;
    }

    char temp[32];
    snprintf(temp, sizeof(temp), "%llu", (unsigned long long)num);

    int j = 0;
    int k = 0;
    int n = strlen(temp);

    for (int i = n - 1; i >= 0; i--) {
        if (k > 0 && k % 3 == 0) {
            buf[j++] = ',';
        }
        buf[j++] = temp[i];
        k++;
    }

    buf[j] = '\0';

    /* Reverse the string */
    for (int i = 0; i < j / 2; i++) {
        char c = buf[i];
        buf[i] = buf[j - 1 - i];
        buf[j - 1 - i] = c;
    }
}