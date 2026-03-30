#ifndef FORMATTER_H
#define FORMATTER_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Format IP address to string */
void format_ip(uint32_t ip, char *buf, size_t len);

/* Format bytes to human readable string (B, KB, MB, GB, TB) */
void format_bytes(uint64_t bytes, char *buf, size_t len);

/* Format bandwidth to human readable string (bps, Kbps, Mbps, Gbps) */
void format_bandwidth(double bps, char *buf, size_t len);

/* Format MAC address to string */
void format_mac(const uint8_t *mac, char *buf, size_t len);

/* Format timestamp to string */
void format_timestamp(time_t t, char *buf, size_t len);

/* Format integer with thousands separator */
void format_number(uint64_t num, char *buf, size_t len);

#endif /* FORMATTER_H */