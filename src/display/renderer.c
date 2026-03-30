#include "renderer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "formatter.h"
#include "../protocol/ip.h"

/* Console renderer private data */
struct console_renderer {
    char ip_buf[16];
    char bytes_buf[32];
    char bandwidth_buf[32];
};

/* Initialize console renderer */
static void console_init(struct renderer *r)
{
    if (!r || !r->private_data) {
        return;
    }

    printf("\033[2J");  /* Clear screen */
    printf("\033[H");   /* Move cursor to home */
}

/* Begin rendering frame */
static void console_begin(struct renderer *r)
{
    (void)r;
    printf("\033[H");   /* Move cursor to home */
}

/* Render statistics */
static void console_render_stats(struct renderer *r, const struct traffic_stats *stats,
                                 double bandwidth)
{
    struct console_renderer *cr = (struct console_renderer *)r->private_data;

    printf("DPDK Traffic Analyzer\n\n");

    /* Packets and bytes */
    format_bytes(stats->total_bytes, cr->bytes_buf, sizeof(cr->bytes_buf));
    format_bandwidth(bandwidth, cr->bandwidth_buf, sizeof(cr->bandwidth_buf));

    printf("Packets: %lu  Bytes: %s  Bandwidth: %s\n\n",
           stats->total_packets, cr->bytes_buf, cr->bandwidth_buf);

    /* Protocol distribution */
    uint64_t total = stats->total_packets > 0 ? stats->total_packets : 1;
    printf("IPv4:%.1f%%  IPv6:%.1f%%  ICMP:%.1f%%  TCP:%.1f%%  UDP:%.1f%%\n\n",
           (stats->ipv4_packets * 100.0) / total,
           (stats->ipv6_packets * 100.0) / total,
           (stats->icmp_packets * 100.0) / total,
           (stats->tcp_packets * 100.0) / total,
           (stats->udp_packets * 100.0) / total);

    /* Application protocols */
    if (stats->http_packets > 0 || stats->https_packets > 0 ||
        stats->dns_packets > 0 || stats->icmp_bytes > 0) {
        printf("HTTP:%lu(%s)  HTTPS:%lu(%s)  DNS:%lu(%s)\n\n",
               stats->http_packets, cr->bytes_buf,
               stats->https_packets, cr->bytes_buf,
               stats->dns_packets, cr->bytes_buf);
    }
}

/* Render top flows */
static void console_render_flows(struct renderer *r, struct flow_entry **flows, int n)
{
    struct console_renderer *cr = (struct console_renderer *)r->private_data;

    printf("Top %d Flows:\n", n);
    for (int i = 0; i < n && flows[i]; i++) {
        format_ip(flows[i]->key.src_ip, cr->ip_buf, sizeof(cr->ip_buf));
        printf("%d. %s:%u->", i + 1, cr->ip_buf, flows[i]->key.src_port);

        format_ip(flows[i]->key.dst_ip, cr->ip_buf, sizeof(cr->ip_buf));
        printf("%s:%u ", cr->ip_buf, flows[i]->key.dst_port);

        format_bytes(flows[i]->byte_count, cr->bytes_buf, sizeof(cr->bytes_buf));
        printf("%lu %s\n", flows[i]->packet_count, cr->bytes_buf);
    }
    printf("\n");
}

/* Render top source IPs */
static void console_render_src_ips(struct renderer *r, struct ip_entry **ips, int n)
{
    struct console_renderer *cr = (struct console_renderer *)r->private_data;

    printf("Top %d Src IPs:\n", n);
    for (int i = 0; i < n && ips[i]; i++) {
        format_ip(ips[i]->ip, cr->ip_buf, sizeof(cr->ip_buf));
        format_bytes(ips[i]->byte_count, cr->bytes_buf, sizeof(cr->bytes_buf));
        printf("%d. %s  %lu %s\n", i + 1, cr->ip_buf, ips[i]->packet_count, cr->bytes_buf);
    }
    printf("\n");
}

/* Render top destination IPs */
static void console_render_dst_ips(struct renderer *r, struct ip_entry **ips, int n)
{
    struct console_renderer *cr = (struct console_renderer *)r->private_data;

    printf("Top %d Dst IPs:\n", n);
    for (int i = 0; i < n && ips[i]; i++) {
        format_ip(ips[i]->ip, cr->ip_buf, sizeof(cr->ip_buf));
        format_bytes(ips[i]->byte_count, cr->bytes_buf, sizeof(cr->bytes_buf));
        printf("%d. %s  %lu %s\n", i + 1, cr->ip_buf, ips[i]->packet_count, cr->bytes_buf);
    }
    printf("\n");
}

/* Render top fingerprints */
static void console_render_fingerprints(struct renderer *r, struct fingerprint_entry **fps, int n)
{
    printf("Top %d JA4:\n", n);
    for (int i = 0; i < n && fps[i]; i++) {
        printf("%d. %s  %lu\n", i + 1, fps[i]->fingerprint, fps[i]->packet_count);
    }
    printf("\n");
}

/* End rendering frame */
static void console_end(struct renderer *r)
{
    (void)r;
    printf("\n");
}

/* Cleanup renderer */
static void console_cleanup(struct renderer *r)
{
    if (r && r->private_data) {
        free(r->private_data);
        r->private_data = NULL;
    }
}

/* Create console renderer */
struct renderer *renderer_console_create(void)
{
    struct renderer *r = calloc(1, sizeof(struct renderer));
    if (!r) {
        return NULL;
    }

    r->private_data = calloc(1, sizeof(struct console_renderer));
    if (!r->private_data) {
        free(r);
        return NULL;
    }

    r->init = console_init;
    r->begin = console_begin;
    r->render_stats = console_render_stats;
    r->render_flows = console_render_flows;
    r->render_src_ips = console_render_src_ips;
    r->render_dst_ips = console_render_dst_ips;
    r->render_fingerprints = console_render_fingerprints;
    r->end = console_end;
    r->cleanup = console_cleanup;

    return r;
}

/* Create JSON renderer (placeholder) */
struct renderer *renderer_json_create(void)
{
    return NULL;
}

/* Destroy renderer */
void renderer_destroy(struct renderer *r)
{
    if (r) {
        if (r->cleanup) {
            r->cleanup(r);
        }
        free(r);
    }
}

/* Helper: render all data using a renderer */
void renderer_render_all(struct renderer *r,
                        const struct traffic_stats *stats,
                        double bandwidth,
                        struct flow_entry **flows,
                        struct ip_entry **src_ips,
                        struct ip_entry **dst_ips,
                        struct fingerprint_entry **fingerprints)
{
    if (!r) {
        return;
    }

    if (r->begin) {
        r->begin(r);
    }

    if (r->render_stats && stats) {
        r->render_stats(r, stats, bandwidth);
    }

    if (r->render_flows && flows) {
        r->render_flows(r, flows, 5);
    }

    if (r->render_src_ips && src_ips) {
        r->render_src_ips(r, src_ips, 5);
    }

    if (r->render_dst_ips && dst_ips) {
        r->render_dst_ips(r, dst_ips, 5);
    }

    if (r->render_fingerprints && fingerprints) {
        r->render_fingerprints(r, fingerprints, 5);
    }

    if (r->end) {
        r->end(r);
    }
}