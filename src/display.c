#include "display.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Initialize display */
void display_init(void)
{
    /* ANSI escape codes for terminal control */
    printf("\033[2J");  /* Clear screen */
    printf("\033[H");   /* Move cursor to top-left */
    fflush(stdout);
}

/* Display statistics */
void display_stats(struct stats_collector *collector)
{
    char bandwidth_str[32];
    char bytes_str[32];

    /* Clear screen and move cursor to top */
    printf("\033[2J\033[H");

    /* Header */
    printf("================================================================================\n");
    printf("DPDK Traffic Analyzer - WSL2\n");
    printf("================================================================================\n");
    printf("Interface: eth0  |  RX Queue: 1  |  Core: 0\n");
    printf("================================================================================\n");

    /* Total statistics */
    format_bandwidth(collector->current.bandwidth, bandwidth_str, sizeof(bandwidth_str));
    format_bytes(collector->current.stats.total_bytes, bytes_str, sizeof(bytes_str));

    printf("Total Statistics:\n");
    printf("  Packets:  %-15llu  |  Bytes:  %s\n",
           (unsigned long long)collector->current.stats.total_packets, bytes_str);
    printf("  Bandwidth:  %s\n\n", bandwidth_str);

    /* Protocol distribution */
    double ipv4_pct = collector->current.stats.total_packets > 0 ?
                      (collector->current.stats.ipv4_packets * 100.0 / collector->current.stats.total_packets) : 0.0;
    double ipv6_pct = collector->current.stats.total_packets > 0 ?
                      (collector->current.stats.ipv6_packets * 100.0 / collector->current.stats.total_packets) : 0.0;
    double tcp_pct = collector->current.stats.total_packets > 0 ?
                     (collector->current.stats.tcp_packets * 100.0 / collector->current.stats.total_packets) : 0.0;
    double udp_pct = collector->current.stats.total_packets > 0 ?
                     (collector->current.stats.udp_packets * 100.0 / collector->current.stats.total_packets) : 0.0;

    printf("Protocol Distribution:\n");
    printf("  IPv4:  %5.1f%%  |  IPv6:  %5.1f%%\n", ipv4_pct, ipv6_pct);
    printf("  TCP:   %5.1f%%  |  UDP:   %5.1f%%\n", tcp_pct, udp_pct);
    printf("\n");

    /* Top flows */
    printf("Top 5 Flows:\n");
    int count = 0;
    for (int i = 0; i < 5; i++) {
        if (collector->current.top_flows[i]) {
            display_flow(collector->current.top_flows[i], i + 1);
            count++;
        }
    }
    if (count == 0) {
        printf("  (No flows detected yet)\n");
    }
    printf("\n");

    /* Footer */
    printf("================================================================================\n");
    printf("[Press Ctrl+C to exit]\n");
    printf("================================================================================\n");

    fflush(stdout);
}

/* Display flow entry */
void display_flow(const struct flow_entry *flow, int rank)
{
    char src_ip[16], dst_ip[16];
    char bytes_str[32];
    const char *protocol = protocol_to_str(flow->key.protocol);

    ip_to_str(flow->key.src_ip, src_ip, sizeof(src_ip));
    ip_to_str(flow->key.dst_ip, dst_ip, sizeof(dst_ip));
    format_bytes(flow->byte_count, bytes_str, sizeof(bytes_str));

    printf("  %d. %s:%-5u  ->  %s:%-5u  (%s)  |  %-10llu pkts  |  %s\n",
           rank, src_ip, ntohs(flow->key.src_port), dst_ip,
           ntohs(flow->key.dst_port), protocol,
           (unsigned long long)flow->packet_count, bytes_str);
}

/* Format bandwidth to string */
void format_bandwidth(double bps, char *str, size_t len)
{
    const char *units[] = {"bps", "Kbps", "Mbps", "Gbps"};
    int unit_idx = 0;
    double value = bps;

    while (value >= 1000.0 && unit_idx < 3) {
        value /= 1000.0;
        unit_idx++;
    }

    snprintf(str, len, "%.2f %s", value, units[unit_idx]);
}

/* Format bytes to human readable string */
void format_bytes(uint64_t bytes, char *str, size_t len)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_idx = 0;
    double value = bytes;

    while (value >= 1024.0 && unit_idx < 4) {
        value /= 1024.0;
        unit_idx++;
    }

    snprintf(str, len, "%.2f %s", value, units[unit_idx]);
}