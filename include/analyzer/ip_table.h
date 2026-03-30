#ifndef IP_TABLE_H
#define IP_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* IP type enumeration */
typedef enum {
    IP_TYPE_SOURCE,
    IP_TYPE_DESTINATION
} ip_type_t;

/* IP entry */
struct ip_entry {
    uint32_t ip;
    uint64_t packet_count;
    uint64_t byte_count;
    struct ip_entry *next;
};

/* IP table */
struct ip_table {
    struct ip_entry **entries;
    uint32_t size;
    uint32_t count;
    ip_type_t type;
};

/* Initialize IP table */
struct ip_table *ip_table_init(uint32_t size, ip_type_t type);

/* Destroy IP table */
void ip_table_destroy(struct ip_table *table);

/* Find or create IP entry */
struct ip_entry *ip_table_lookup(struct ip_table *table, uint32_t ip);

/* Update IP statistics */
void ip_table_update(struct ip_entry *entry, uint32_t len);

/* Get top N IPs by packet count */
void ip_table_get_top(struct ip_table *table, struct ip_entry **top, uint32_t n);

/* Get table type */
static inline ip_type_t ip_table_type(const struct ip_table *table)
{
    return table->type;
}

/* Get table statistics */
uint32_t ip_table_count(const struct ip_table *table);
uint32_t ip_table_size(const struct ip_table *table);

/* Hash function for IP address */
static inline uint32_t ip_hash(uint32_t ip, uint32_t table_size)
{
    uint32_t hash = 5381;
    const uint8_t *p = (const uint8_t *)&ip;

    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        hash = ((hash << 5) + hash) + p[i];
    }

    return hash % table_size;
}

#endif /* IP_TABLE_H */