#ifndef RENDERER_H
#define RENDERER_H

#include <stddef.h>
#include <stdbool.h>
#include "../stats/traffic_stats.h"
#include "../analyzer/flow_table.h"
#include "../analyzer/ip_table.h"
#include "../analyzer/fingerprint_table.h"
#include "../analyzer/geolocation.h"

/* Renderer interface */
struct renderer {
    void *private_data;

    /* Initialize renderer */
    void (*init)(struct renderer *r);

    /* Begin rendering frame */
    void (*begin)(struct renderer *r);

    /* Render statistics */
    void (*render_stats)(struct renderer *r, const struct traffic_stats *stats,
                        double bandwidth);

    /* Render top flows */
    void (*render_flows)(struct renderer *r, struct flow_entry **flows, int n);

    /* Render top source IPs */
    void (*render_src_ips)(struct renderer *r, struct ip_entry **ips, int n, const struct geo_db *geo_db);

    /* Render top destination IPs */
    void (*render_dst_ips)(struct renderer *r, struct ip_entry **ips, int n, const struct geo_db *geo_db);

    /* Render top fingerprints */
    void (*render_fingerprints)(struct renderer *r, struct fingerprint_entry **fps, int n);

    /* End rendering frame */
    void (*end)(struct renderer *r);

    /* Cleanup renderer */
    void (*cleanup)(struct renderer *r);
};

/* Create console renderer */
struct renderer *renderer_console_create(void);

/* Create JSON renderer */
struct renderer *renderer_json_create(void);

/* Destroy renderer */
void renderer_destroy(struct renderer *r);

/* Helper: render all data using a renderer */
void renderer_render_all(struct renderer *r,
                        const struct traffic_stats *stats,
                        double bandwidth,
                        struct flow_entry **flows,
                        struct ip_entry **src_ips,
                        struct ip_entry **dst_ips,
                        struct fingerprint_entry **fingerprints,
                        const struct geo_db *geo_db);

#endif /* RENDERER_H */