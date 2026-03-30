#ifndef FINGERPRINT_TABLE_H
#define FINGERPRINT_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Fingerprint entry */
struct fingerprint_entry {
    char fingerprint[64];
    uint64_t packet_count;
    struct fingerprint_entry *next;
};

/* Fingerprint table */
struct fingerprint_table {
    struct fingerprint_entry **entries;
    uint32_t size;
    uint32_t count;
};

/* Initialize fingerprint table */
struct fingerprint_table *fingerprint_table_init(uint32_t size);

/* Destroy fingerprint table */
void fingerprint_table_destroy(struct fingerprint_table *table);

/* Find or create fingerprint entry */
struct fingerprint_entry *fingerprint_table_lookup(struct fingerprint_table *table,
                                                   const char *fingerprint);

/* Update fingerprint statistics */
void fingerprint_table_update(struct fingerprint_entry *entry);

/* Get top N fingerprints by packet count */
void fingerprint_table_get_top(struct fingerprint_table *table,
                                struct fingerprint_entry **top,
                                uint32_t n);

/* Get table statistics */
uint32_t fingerprint_table_count(const struct fingerprint_table *table);
uint32_t fingerprint_table_size(const struct fingerprint_table *table);

/* Hash function for fingerprint string */
static inline uint32_t fingerprint_hash(const char *fp, uint32_t table_size)
{
    uint32_t hash = 5381;

    for (size_t i = 0; fp[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + (uint8_t)fp[i];
    }

    return hash % table_size;
}

#endif /* FINGERPRINT_TABLE_H */