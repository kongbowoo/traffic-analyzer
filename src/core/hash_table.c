#include "hash_table.h"
#include <stdlib.h>
#include <string.h>

/* Initialize hash table */
struct hash_table *hash_table_init(uint32_t size,
                                   hash_fn_t hash_fn,
                                   compare_fn_t compare_fn)
{
    struct hash_table *table = calloc(1, sizeof(struct hash_table));
    if (!table) {
        return NULL;
    }

    table->entries = calloc(size, sizeof(struct hash_entry *));
    if (!table->entries) {
        free(table);
        return NULL;
    }

    table->size = size;
    table->count = 0;
    table->hash_fn = hash_fn;
    table->compare_fn = compare_fn;

    return table;
}

/* Destroy hash table (does not free keys/values) */
void hash_table_destroy(struct hash_table *table)
{
    if (!table) {
        return;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct hash_entry *entry = table->entries[i];
        while (entry) {
            struct hash_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(table->entries);
    free(table);
}

/* Destroy hash table and free all entries */
void hash_table_destroy_full(struct hash_table *table,
                             void (*key_free)(void *key),
                             void (*value_free)(void *value))
{
    if (!table) {
        return;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct hash_entry *entry = table->entries[i];
        while (entry) {
            struct hash_entry *next = entry->next;
            if (key_free && entry->key) {
                key_free(entry->key);
            }
            if (value_free && entry->value) {
                value_free(entry->value);
            }
            free(entry);
            entry = next;
        }
    }

    free(table->entries);
    free(table);
}

/* Lookup value by key */
void *hash_table_lookup(struct hash_table *table, const void *key)
{
    if (!table || !key) {
        return NULL;
    }

    uint32_t idx = table->hash_fn(key, table->size);
    struct hash_entry *entry = table->entries[idx];

    while (entry) {
        if (table->compare_fn(key, entry->key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }

    return NULL;
}

/* Insert key-value pair (returns existing value if key exists) */
void *hash_table_insert(struct hash_table *table, void *key, void *value)
{
    if (!table || !key) {
        return NULL;
    }

    uint32_t idx = table->hash_fn(key, table->size);
    struct hash_entry *entry = table->entries[idx];

    /* Check if key already exists */
    while (entry) {
        if (table->compare_fn(key, entry->key) == 0) {
            void *old_value = entry->value;
            entry->value = value;
            return old_value;
        }
        entry = entry->next;
    }

    /* Create new entry */
    entry = malloc(sizeof(struct hash_entry));
    if (!entry) {
        return NULL;
    }

    entry->key = key;
    entry->value = value;
    entry->next = table->entries[idx];
    table->entries[idx] = entry;
    table->count++;

    return NULL;
}

/* Remove entry by key (returns removed value or NULL) */
void *hash_table_remove(struct hash_table *table, const void *key)
{
    if (!table || !key) {
        return NULL;
    }

    uint32_t idx = table->hash_fn(key, table->size);
    struct hash_entry **entry_ptr = &table->entries[idx];

    while (*entry_ptr) {
        if (table->compare_fn(key, (*entry_ptr)->key) == 0) {
            struct hash_entry *entry = *entry_ptr;
            void *value = entry->value;
            *entry_ptr = entry->next;
            free(entry);
            table->count--;
            return value;
        }
        entry_ptr = &(*entry_ptr)->next;
    }

    return NULL;
}

/* Get all entries (caller must free the returned array) */
struct hash_entry **hash_table_get_all(struct hash_table *table, uint32_t *count)
{
    if (!table || !count) {
        return NULL;
    }

    *count = table->count;
    if (table->count == 0) {
        return NULL;
    }

    struct hash_entry **entries = malloc(table->count * sizeof(struct hash_entry *));
    if (!entries) {
        return NULL;
    }

    uint32_t pos = 0;
    for (uint32_t i = 0; i < table->size; i++) {
        struct hash_entry *entry = table->entries[i];
        while (entry && pos < table->count) {
            entries[pos++] = entry;
            entry = entry->next;
        }
    }

    return entries;
}

/* Iterate over all entries */
int hash_table_foreach(struct hash_table *table, hash_iterate_fn fn, void *user_data)
{
    if (!table || !fn) {
        return -1;
    }

    for (uint32_t i = 0; i < table->size; i++) {
        struct hash_entry *entry = table->entries[i];
        while (entry) {
            int ret = fn(entry->key, entry->value, user_data);
            if (ret != 0) {
                return ret;
            }
            entry = entry->next;
        }
    }

    return 0;
}

/* Get table size */
uint32_t hash_table_size(const struct hash_table *table)
{
    return table ? table->size : 0;
}

/* Get entry count */
uint32_t hash_table_count(const struct hash_table *table)
{
    return table ? table->count : 0;
}

/* Common hash functions */
uint32_t hash_string(const void *key, uint32_t table_size)
{
    const char *str = (const char *)key;
    uint32_t hash = 5381;

    for (size_t i = 0; str[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + (uint8_t)str[i];
    }

    return hash % table_size;
}

uint32_t hash_uint32(const void *key, uint32_t table_size)
{
    uint32_t value = *(const uint32_t *)key;
    value ^= value >> 16;
    value *= 0x85ebca6b;
    value ^= value >> 13;
    value *= 0xc2b2ae35;
    value ^= value >> 16;
    return value % table_size;
}

uint32_t hash_bytes(const void *key, size_t len, uint32_t table_size)
{
    const uint8_t *p = (const uint8_t *)key;
    uint32_t hash = 5381;

    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + p[i];
    }

    return hash % table_size;
}

/* Common compare functions */
int compare_string(const void *k1, const void *k2)
{
    return strcmp((const char *)k1, (const char *)k2);
}

int compare_uint32(const void *k1, const void *k2)
{
    uint32_t v1 = *(const uint32_t *)k1;
    uint32_t v2 = *(const uint32_t *)k2;
    return (v1 < v2) ? -1 : ((v1 > v2) ? 1 : 0);
}

int compare_bytes(const void *k1, const void *k2, size_t len)
{
    return memcmp(k1, k2, len);
}