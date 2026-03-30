#ifndef GEOLOCATION_H
#define GEOLOCATION_H

#include <stdint.h>
#include <stdbool.h>

/* Geolocation record */
struct geo_record {
    uint32_t start_ip;
    uint32_t end_ip;
    char country_code[4];  /* ISO 3166-1 alpha-2 */
    char region[32];
    char city[32];
};

/* Geolocation database */
struct geo_db {
    struct geo_record *records;
    uint32_t count;
    uint32_t capacity;
};

/* Initialize geolocation database with built-in data */
struct geo_db *geo_db_init(void);

/* Destroy geolocation database */
void geo_db_destroy(struct geo_db *db);

/* Load geolocation database from file */
struct geo_db *geo_db_load(const char *path);

/* Lookup country code by IP address */
const char *geo_lookup_country(const struct geo_db *db, uint32_t ip);

/* Lookup full geolocation by IP address */
const struct geo_record *geo_lookup(const struct geo_db *db, uint32_t ip);

/* Check if IP is in database */
bool geo_contains(const struct geo_db *db, uint32_t ip);

/* Get database record count */
uint32_t geo_db_count(const struct geo_db *db);

#endif /* GEOLOCATION_H */