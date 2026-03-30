#ifndef COUNTERS_H
#define COUNTERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Generic counter entry */
struct counter_entry {
    char name[32];
    uint64_t packets;
    uint64_t bytes;
    struct counter_entry *next;
};

/* Counter registry */
struct counter_registry {
    struct counter_entry *head;
    uint32_t count;
};

/* Initialize counter registry */
struct counter_registry *counter_registry_init(void);

/* Destroy counter registry */
void counter_registry_destroy(struct counter_registry *reg);

/* Register a new counter */
struct counter_entry *counter_register(struct counter_registry *reg, const char *name);

/* Find counter by name */
struct counter_entry *counter_find(struct counter_registry *reg, const char *name);

/* Increment counter packets */
void counter_inc_packets(struct counter_entry *entry, uint64_t count);

/* Increment counter bytes */
void counter_inc_bytes(struct counter_entry *entry, uint64_t bytes);

/* Get counter value */
uint64_t counter_get_packets(const struct counter_entry *entry);
uint64_t counter_get_bytes(const struct counter_entry *entry);

/* Get all counters (returns NULL-terminated array) */
struct counter_entry **counter_get_all(struct counter_registry *reg);

/* Get counter count */
uint32_t counter_registry_count(const struct counter_registry *reg);

#endif /* COUNTERS_H */