#ifndef DISPLAY_H
#define DISPLAY_H

#include "stats_collector.h"
#include "packet_parser.h"

/* Initialize display */
void display_init(void);

/* Display statistics */
void display_stats(struct stats_collector *collector);

/* Display flow entry */
void display_flow(const struct flow_entry *flow, int rank);

/* Format bandwidth to string */
void format_bandwidth(double bps, char *str, size_t len);

/* Format bytes to human readable string */
void format_bytes(uint64_t bytes, char *str, size_t len);

#endif /* DISPLAY_H */