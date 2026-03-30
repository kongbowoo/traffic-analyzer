#include "types.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Initialize buffer */
struct buffer *buffer_init(size_t initial_capacity)
{
    struct buffer *buf = calloc(1, sizeof(struct buffer));
    if (!buf) {
        return NULL;
    }

    buf->data = malloc(initial_capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->size = 0;
    buf->capacity = initial_capacity;

    return buf;
}

/* Destroy buffer */
void buffer_destroy(struct buffer *buf)
{
    if (!buf) {
        return;
    }

    free(buf->data);
    free(buf);
}

/* Append data to buffer */
result_t buffer_append(struct buffer *buf, const uint8_t *data, size_t len)
{
    if (!buf || !data) {
        return RESULT_INVALID_PARAM;
    }

    /* Check if we need to expand */
    if (buf->size + len > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        while (new_capacity < buf->size + len) {
            new_capacity *= 2;
        }

        uint8_t *new_data = realloc(buf->data, new_capacity);
        if (!new_data) {
            return RESULT_NO_MEMORY;
        }

        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    memcpy(buf->data + buf->size, data, len);
    buf->size += len;

    return RESULT_OK;
}

/* Clear buffer (keep capacity) */
void buffer_clear(struct buffer *buf)
{
    if (buf) {
        buf->size = 0;
    }
}

/* Get buffer data pointer */
uint8_t *buffer_data(const struct buffer *buf)
{
    return buf ? buf->data : NULL;
}

/* Get current buffer size */
size_t buffer_size(const struct buffer *buf)
{
    return buf ? buf->size : 0;
}