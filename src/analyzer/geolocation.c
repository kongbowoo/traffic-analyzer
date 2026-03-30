#include "geolocation.h"
#include <stdlib.h>
#include <string.h>

/* Initialize geolocation database with built-in data */
struct geo_db *geo_db_init(void)
{
    struct geo_db *db = calloc(1, sizeof(struct geo_db));
    if (!db) {
        return NULL;
    }

    /* Common IP ranges and their countries (simplified for demo) */
    static const struct geo_record built_in_db[] = {
        /* China */
        {0x14000000, 0x14FFFFFF, "CN", "", ""},
        {0x1A000000, 0x1AFFFFFF, "CN", "", ""},
        {0x3A000000, 0x3AFFFFFF, "CN", "", ""},
        {0x40000000, 0x40FFFFFF, "CN", "", ""},
        {0x46000000, 0x46FFFFFF, "CN", "", ""},
        {0x4A000000, 0x4AFFFFFF, "CN", "", ""},
        {0x58000000, 0x58FFFFFF, "CN", "", ""},
        {0x60000000, 0x60FFFFFF, "CN", "", ""},
        {0x6A000000, 0x6AFFFFFF, "CN", "", ""},
        {0x76000000, 0x76FFFFFF, "CN", "", ""},
        {0x7A000000, 0x7AFFFFFF, "CN", "", ""},
        {0xA0000000, 0xA0FFFFFF, "CN", "", ""},
        {0xA4000000, 0xA4FFFFFF, "CN", "", ""},
        {0xB0000000, 0xB0FFFFFF, "CN", "", ""},
        {0xB4000000, 0xB4FFFFFF, "CN", "", ""},
        {0xC0000000, 0xC0FFFFFF, "CN", "", ""},
        {0xC6000000, 0xC6FFFFFF, "CN", "", ""},
        {0xCA000000, 0xCAFFFFFF, "CN", "", ""},
        {0xD0000000, 0xD0FFFFFF, "CN", "", ""},
        {0xD4000000, 0xD4FFFFFF, "CN", "", ""},
        {0xE0000000, 0xE0FFFFFF, "CN", "", ""},
        {0xE4000000, 0xE4FFFFFF, "CN", "", ""},
        {0xF0000000, 0xF0FFFFFF, "CN", "", ""},
        {0xF2000000, 0xF2FFFFFF, "CN", "", ""},
        /* United States */
        {0x03000000, 0x0FFFFFFF, "US", "", ""},
        {0x13000000, 0x13FFFFFF, "US", "", ""},
        {0x2D000000, 0x2DFFFFFF, "US", "", ""},
        {0x34000000, 0x34FFFFFF, "US", "", ""},
        {0x4B000000, 0x4BFFFFFF, "US", "", ""},
        {0x50000000, 0x50FFFFFF, "US", "", ""},
        {0x59000000, 0x59FFFFFF, "US", "", ""},
        {0x64000000, 0x64FFFFFF, "US", "", ""},
        {0x6E000000, 0x6EFFFFFF, "US", "", ""},
        {0x73000000, 0x73FFFFFF, "US", "", ""},
        {0x88000000, 0x88FFFFFF, "US", "", ""},
        {0x8C000000, 0x8CFFFFFF, "US", "", ""},
        {0x95000000, 0x95FFFFFF, "US", "", ""},
        {0x9B000000, 0x9BFFFFFF, "US", "", ""},
        {0x9C000000, 0x9CFFFFFF, "US", "", ""},
        {0x9D000000, 0x9DFFFFFF, "US", "", ""},
        {0xA1000000, 0xA1FFFFFF, "US", "", ""},
        {0xA2000000, 0xA2FFFFFF, "US", "", ""},
        {0xA3000000, 0xA3FFFFFF, "US", "", ""},
        {0xAB000000, 0xABFFFFFF, "US", "", ""},
        {0xAC000000, 0xACFFFFFF, "US", "", ""},
        {0xAD000000, 0xADFFFFFF, "US", "", ""},
        {0xAE000000, 0xAEFFFFFF, "US", "", ""},
        {0xB0000000, 0xB0FFFFFF, "US", "", ""},
        {0xB1000000, 0xB1FFFFFF, "US", "", ""},
        {0xB2000000, 0xB2FFFFFF, "US", "", ""},
        {0xB6000000, 0xB6FFFFFF, "US", "", ""},
        {0xB8000000, 0xB8FFFFFF, "US", "", ""},
        {0xBA000000, 0xBAFFFFFF, "US", "", ""},
        {0xBB000000, 0xBBFFFFFF, "US", "", ""},
        {0xBD000000, 0xBDFFFFFF, "US", "", ""},
        {0xBE000000, 0xBEFFFFFF, "US", "", ""},
        {0xC0000000, 0xC0FFFFFF, "US", "", ""},
        {0xC1000000, 0xC1FFFFFF, "US", "", ""},
        {0xC2000000, 0xC2FFFFFF, "US", "", ""},
        {0xC3000000, 0xC3FFFFFF, "US", "", ""},
        {0xC4000000, 0xC4FFFFFF, "US", "", ""},
        {0xC5000000, 0xC5FFFFFF, "US", "", ""},
        {0xC6000000, 0xC6FFFFFF, "US", "", ""},
        {0xC7000000, 0xC7FFFFFF, "US", "", ""},
        {0xC8000000, 0xC8FFFFFF, "US", "", ""},
        {0xC9000000, 0xC9FFFFFF, "US", "", ""},
        {0xCA000000, 0xCAFFFFFF, "US", "", ""},
        {0xCC000000, 0xCCFFFFFF, "US", "", ""},
        {0xCD000000, 0xCDFFFFFF, "US", "", ""},
        {0xD0000000, 0xD0FFFFFF, "US", "", ""},
        {0xD1000000, 0xD1FFFFFF, "US", "", ""},
        {0xD2000000, 0xD2FFFFFF, "US", "", ""},
        {0xD3000000, 0xD3FFFFFF, "US", "", ""},
        {0xD4000000, 0xD4FFFFFF, "US", "", ""},
        {0xD5000000, 0xD5FFFFFF, "US", "", ""},
        {0xD6000000, 0xD6FFFFFF, "US", "", ""},
        {0xD8000000, 0xD8FFFFFF, "US", "", ""},
        {0xD9000000, 0xD9FFFFFF, "US", "", ""},
        {0xDA000000, 0xDAFFFFFF, "US", "", ""},
        {0xDC000000, 0xDCFFFFFF, "US", "", ""},
        {0xDD000000, 0xDDFFFFFF, "US", "", ""},
        {0xDE000000, 0xDEFFFFFF, "US", "", ""},
        {0xE0000000, 0xE0FFFFFF, "US", "", ""},
        {0xE1000000, 0xE1FFFFFF, "US", "", ""},
        {0xE2000000, 0xE2FFFFFF, "US", "", ""},
        {0xE3000000, 0xE3FFFFFF, "US", "", ""},
        {0xE4000000, 0xE4FFFFFF, "US", "", ""},
        {0xE5000000, 0xE5FFFFFF, "US", "", ""},
        {0xE6000000, 0xE6FFFFFF, "US", "", ""},
        {0xE7000000, 0xE7FFFFFF, "US", "", ""},
        {0xE8000000, 0xE8FFFFFF, "US", "", ""},
        {0xE9000000, 0xE9FFFFFF, "US", "", ""},
        {0xEA000000, 0xEAFFFFFF, "US", "", ""},
        {0xEB000000, 0xEBFFFFFF, "US", "", ""},
        {0xEC000000, 0xECFFFFFF, "US", "", ""},
        {0xED000000, 0xEDFFFFFF, "US", "", ""},
        {0xEE000000, 0xEEFFFFFF, "US", "", ""},
        {0xEF000000, 0xEFFFFFFF, "US", "", ""},
        {0xF0000000, 0xF0FFFFFF, "US", "", ""},
        {0xF1000000, 0xF1FFFFFF, "US", "", ""},
        {0xF2000000, 0xF2FFFFFF, "US", "", ""},
        {0xF3000000, 0xF3FFFFFF, "US", "", ""},
        {0xF4000000, 0xF4FFFFFF, "US", "", ""},
        {0xF5000000, 0xF5FFFFFF, "US", "", ""},
        {0xF6000000, 0xF6FFFFFF, "US", "", ""},
        {0xF7000000, 0xF7FFFFFF, "US", "", ""},
        {0xF8000000, 0xF8FFFFFF, "US", "", ""},
        {0xF9000000, 0xF9FFFFFF, "US", "", ""},
        {0xFA000000, 0xFAFFFFFF, "US", "", ""},
        {0xFB000000, 0xFBFFFFFF, "US", "", ""},
        {0xFC000000, 0xFCFFFFFF, "US", "", ""},
        {0xFD000000, 0xFDFFFFFF, "US", "", ""},
        {0xFE000000, 0xFEFFFFFF, "US", "", ""},
        {0xFF000000, 0xFFFFFFFF, "US", "", ""},
        /* Japan */
        {0x24000000, 0x24FFFFFF, "JP", "", ""},
        {0x25000000, 0x25FFFFFF, "JP", "", ""},
        {0x26000000, 0x26FFFFFF, "JP", "", ""},
        /* Germany */
        {0x2A000000, 0x2AFFFFFF, "DE", "", ""},
        {0x37000000, 0x37FFFFFF, "DE", "", ""},
        {0x44000000, 0x44FFFFFF, "DE", "", ""},
        {0x54000000, 0x54FFFFFF, "DE", "", ""},
        {0x55000000, 0x55FFFFFF, "DE", "", ""},
        {0x56000000, 0x56FFFFFF, "DE", "", ""},
        {0x57000000, 0x57FFFFFF, "DE", "", ""},
        {0x5B000000, 0x5BFFFFFF, "DE", "", ""},
        {0x62000000, 0x62FFFFFF, "DE", "", ""},
        {0x63000000, 0x63FFFFFF, "DE", "", ""},
        {0x66000000, 0x66FFFFFF, "DE", "", ""},
        {0x67000000, 0x67FFFFFF, "DE", "", ""},
        {0x68000000, 0x68FFFFFF, "DE", "", ""},
        {0x69000000, 0x69FFFFFF, "DE", "", ""},
        {0x6B000000, 0x6BFFFFFF, "DE", "", ""},
        {0x6C000000, 0x6CFFFFFF, "DE", "", ""},
        {0x6D000000, 0x6DFFFFFF, "DE", "", ""},
        {0x71000000, 0x71FFFFFF, "DE", "", ""},
        {0x77000000, 0x77FFFFFF, "DE", "", ""},
        {0x78000000, 0x78FFFFFF, "DE", "", ""},
        {0x79000000, 0x79FFFFFF, "DE", "", ""},
        {0x7B000000, 0x7BFFFFFF, "DE", "", ""},
        {0x7C000000, 0x7CFFFFFF, "DE", "", ""},
        {0x7D000000, 0x7DFFFFFF, "DE", "", ""},
        {0x7E000000, 0x7EFFFFFF, "DE", "", ""},
        {0x7F000000, 0x7FFFFFFF, "DE", "", ""},
        /* United Kingdom */
        {0x02000000, 0x02FFFFFF, "UK", "", ""},
        {0x1D000000, 0x1DFFFFFF, "UK", "", ""},
        {0x1E000000, 0x1EFFFFFF, "UK", "", ""},
        {0x2E000000, 0x2EFFFFFF, "UK", "", ""},
        {0x4E000000, 0x4EFFFFFF, "UK", "", ""},
        {0x51000000, 0x51FFFFFF, "UK", "", ""},
        {0x52000000, 0x52FFFFFF, "UK", "", ""},
        {0x53000000, 0x53FFFFFF, "UK", "", ""},
        {0x5A000000, 0x5AFFFFFF, "UK", "", ""},
        {0x61000000, 0x61FFFFFF, "UK", "", ""},
        {0x6F000000, 0x6FFFFFFF, "UK", "", ""},
        {0x72000000, 0x72FFFFFF, "UK", "", ""},
        {0x74000000, 0x74FFFFFF, "UK", "", ""},
        {0x75000000, 0x75FFFFFF, "UK", "", ""},
        /* Russia (simplified - just a few ranges) */
        {0x10000000, 0x10FFFFFF, "RU", "", ""},
        {0x29000000, 0x29FFFFFF, "RU", "", ""},
        {0x2F000000, 0x2FFFFFFF, "RU", "", ""},
        /* France (simplified) */
        {0x05000000, 0x05FFFFFF, "FR", "", ""},
        {0x09000000, 0x09FFFFFF, "FR", "", ""},
        {0x0A000000, 0x0AFFFFFF, "FR", "", ""},
        /* South Korea (simplified) */
        {0x3B000000, 0x3BFFFFFF, "KR", "", ""},
        {0x58000000, 0x58FFFFFF, "KR", "", ""},
        {0x5E000000, 0x5EFFFFFF, "KR", "", ""},
        /* Brazil (simplified) */
        {0x01800000, 0x019FFFFF, "BR", "", ""},
        {0x04000000, 0x04FFFFFF, "BR", "", ""},
        /* India (simplified) */
        {0x01000000, 0x01FFFFFF, "IN", "", ""},
        {0x01400000, 0x014FFFFF, "IN", "", ""},
        /* Canada (simplified) */
        {0x24000000, 0x24FFFFFF, "CA", "", ""},
        {0x25000000, 0x25FFFFFF, "CA", "", ""},
        /* Australia (simplified) */
        {0x01000000, 0x01FFFFFF, "AU", "", ""},
        {0x01400000, 0x014FFFFF, "AU", "", ""},
    };

    size_t count = sizeof(built_in_db) / sizeof(built_in_db[0]);
    db->records = malloc(count * sizeof(struct geo_record));
    if (!db->records) {
        free(db);
        return NULL;
    }

    memcpy(db->records, built_in_db, count * sizeof(struct geo_record));
    db->count = count;
    db->capacity = count;

    return db;
}

/* Destroy geolocation database */
void geo_db_destroy(struct geo_db *db)
{
    if (!db) {
        return;
    }

    free(db->records);
    free(db);
}

/* Load geolocation database from file */
struct geo_db *geo_db_load(const char *path)
{
    /* TODO: Implement file loading */
    return geo_db_init();
}

/* Lookup country code by IP address */
const char *geo_lookup_country(const struct geo_db *db, uint32_t ip)
{
    if (!db) {
        return "??";
    }

    for (uint32_t i = 0; i < db->count; i++) {
        if (ip >= db->records[i].start_ip && ip <= db->records[i].end_ip) {
            return db->records[i].country_code;
        }
    }

    return "??";
}

/* Lookup full geolocation by IP address */
const struct geo_record *geo_lookup(const struct geo_db *db, uint32_t ip)
{
    if (!db) {
        return NULL;
    }

    for (uint32_t i = 0; i < db->count; i++) {
        if (ip >= db->records[i].start_ip && ip <= db->records[i].end_ip) {
            return &db->records[i];
        }
    }

    return NULL;
}

/* Check if IP is in database */
bool geo_contains(const struct geo_db *db, uint32_t ip)
{
    return geo_lookup(db, ip) != NULL;
}

/* Get database record count */
uint32_t geo_db_count(const struct geo_db *db)
{
    return db ? db->count : 0;
}