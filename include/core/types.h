#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef USE_DPDK
    #include <rte_byteorder.h>

    static inline uint16_t rte_be_to_cpu_16_compat(uint16_t x) {
        return rte_be_to_cpu_16(x);
    }
    static inline uint32_t rte_be_to_cpu_32_compat(uint32_t x) {
        return rte_be_to_cpu_32(x);
    }
    static inline uint32_t rte_cpu_to_be_32_compat(uint32_t x) {
        return rte_cpu_to_be_32(x);
    }
#else
    /* Non-DPDK byte order conversion functions */
    static inline uint16_t rte_be_to_cpu_16_compat(uint16_t x) {
        return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF);
    }
    static inline uint32_t rte_be_to_cpu_32_compat(uint32_t x) {
        return ((x >> 24) & 0xFF) |
               ((x >> 8) & 0xFF00) |
               ((x & 0xFF00) << 8) |
               ((x & 0xFF) << 24);
    }
    static inline uint32_t rte_cpu_to_be_32_compat(uint32_t x) {
        return rte_be_to_cpu_32_compat(x);
    }
#endif

/* Generic result type */
typedef enum {
    RESULT_OK = 0,
    RESULT_ERROR = -1,
    RESULT_INVALID_PARAM = -2,
    RESULT_NO_MEMORY = -3,
    RESULT_NOT_FOUND = -4
} result_t;

/* Generic key-value pair */
struct kv_pair {
    const char *key;
    const char *value;
};

/* Generic buffer */
struct buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
};

/* Initialize buffer */
struct buffer *buffer_init(size_t initial_capacity);

/* Destroy buffer */
void buffer_destroy(struct buffer *buf);

/* Append data to buffer */
result_t buffer_append(struct buffer *buf, const uint8_t *data, size_t len);

/* Clear buffer (keep capacity) */
void buffer_clear(struct buffer *buf);

/* Get buffer data pointer */
uint8_t *buffer_data(const struct buffer *buf);

/* Get current buffer size */
size_t buffer_size(const struct buffer *buf);

/* Generic cleanup function pointer */
typedef void (*cleanup_fn)(void *data);

#endif /* TYPES_H */