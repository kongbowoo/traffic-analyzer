#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stddef.h>
#include <stdint.h>

/* Generic hash function pointer */
typedef uint32_t (*hash_fn_t)(const void *key, uint32_t table_size);

/* Generic compare function pointer */
typedef int (*compare_fn_t)(const void *k1, const void *k2);

/* Generic hash table entry */
struct hash_entry {
    void *key;
    void *value;
    struct hash_entry *next;
};

/* Generic hash table */
struct hash_table {
    struct hash_entry **entries;
    uint32_t size;
    uint32_t count;
    hash_fn_t hash_fn;
    compare_fn_t compare_fn;
};

/* Initialize hash table */
struct hash_table *hash_table_init(uint32_t size,
                                   hash_fn_t hash_fn,
                                   compare_fn_t compare_fn);

/* Destroy hash table (does not free keys/values) */
void hash_table_destroy(struct hash_table *table);

/* Destroy hash table and free all entries (with custom free functions) */
void hash_table_destroy_full(struct hash_table *table,
                             void (*key_free)(void *key),
                             void (*value_free)(void *value));

/* Lookup value by key */
void *hash_table_lookup(struct hash_table *table, const void *key);

/* Insert key-value pair (returns existing value if key exists) */
void *hash_table_insert(struct hash_table *table, void *key, void *value);

/* Remove entry by key (returns removed value or NULL) */
void *hash_table_remove(struct hash_table *table, const void *key);

/* Get all entries (caller must free the returned array) */
struct hash_entry **hash_table_get_all(struct hash_table *table, uint32_t *count);

/* Iterate over all entries */
typedef int (*hash_iterate_fn)(void *key, void *value, void *user_data);
int hash_table_foreach(struct hash_table *table, hash_iterate_fn fn, void *user_data);

/* Get table size */
uint32_t hash_table_size(const struct hash_table *table);

/* Get entry count */
uint32_t hash_table_count(const struct hash_table *table);

/* Common hash functions */
uint32_t hash_string(const void *key, uint32_t table_size);
uint32_t hash_uint32(const void *key, uint32_t table_size);
uint32_t hash_bytes(const void *key, size_t len, uint32_t table_size);

/* Common compare functions */
int compare_string(const void *k1, const void *k2);
int compare_uint32(const void *k1, const void *k2);
int compare_bytes(const void *k1, const void *k2, size_t len);

#endif /* HASH_TABLE_H */