#include "counters.h"
#include <stdlib.h>
#include <string.h>

/* Initialize counter registry */
struct counter_registry *counter_registry_init(void)
{
    return calloc(1, sizeof(struct counter_registry));
}

/* Destroy counter registry */
void counter_registry_destroy(struct counter_registry *reg)
{
    if (!reg) {
        return;
    }

    struct counter_entry *entry = reg->head;
    while (entry) {
        struct counter_entry *next = entry->next;
        free(entry);
        entry = next;
    }

    free(reg);
}

/* Register a new counter */
struct counter_entry *counter_register(struct counter_registry *reg, const char *name)
{
    if (!reg || !name) {
        return NULL;
    }

    struct counter_entry *entry = counter_find(reg, name);
    if (entry) {
        return entry;
    }

    entry = calloc(1, sizeof(struct counter_entry));
    if (!entry) {
        return NULL;
    }

    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';

    entry->next = reg->head;
    reg->head = entry;
    reg->count++;

    return entry;
}

/* Find counter by name */
struct counter_entry *counter_find(struct counter_registry *reg, const char *name)
{
    if (!reg || !name) {
        return NULL;
    }

    struct counter_entry *entry = reg->head;
    while (entry) {
        if (strcmp(entry->name, name) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

/* Increment counter packets */
void counter_inc_packets(struct counter_entry *entry, uint64_t count)
{
    if (entry) {
        entry->packets += count;
    }
}

/* Increment counter bytes */
void counter_inc_bytes(struct counter_entry *entry, uint64_t bytes)
{
    if (entry) {
        entry->bytes += bytes;
    }
}

/* Get counter value */
uint64_t counter_get_packets(const struct counter_entry *entry)
{
    return entry ? entry->packets : 0;
}

uint64_t counter_get_bytes(const struct counter_entry *entry)
{
    return entry ? entry->bytes : 0;
}

/* Get all counters (returns NULL-terminated array) */
struct counter_entry **counter_get_all(struct counter_registry *reg)
{
    if (!reg || reg->count == 0) {
        return NULL;
    }

    struct counter_entry **entries = calloc(reg->count + 1, sizeof(struct counter_entry *));
    if (!entries) {
        return NULL;
    }

    struct counter_entry *entry = reg->head;
    uint32_t i = 0;
    while (entry && i < reg->count) {
        entries[i++] = entry;
        entry = entry->next;
    }

    return entries;
}

/* Get counter count */
uint32_t counter_registry_count(const struct counter_registry *reg)
{
    return reg ? reg->count : 0;
}