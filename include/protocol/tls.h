#ifndef TLS_H
#define TLS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* TLS Record Type */
#define TLS_TYPE_CHANGE_CIPHER_SPEC  20
#define TLS_TYPE_ALERT               21
#define TLS_TYPE_HANDSHAKE           22
#define TLS_TYPE_APPLICATION_DATA    23

/* TLS Handshake Type */
#define TLS_HS_CLIENT_HELLO          1
#define TLS_HS_SERVER_HELLO          2
#define TLS_HS_CERTIFICATE           11
#define TLS_HS_SERVER_KEY_EXCH       12
#define TLS_HS_CERTIFICATE_REQUEST   13
#define TLS_HS_SERVER_HELLO_DONE     14
#define TLS_HS_CERTIFICATE_VERIFY    15
#define TLS_HS_CLIENT_KEY_EXCH       16
#define TLS_HS_FINISHED              20

/* TLS Version */
#define TLS_VERSION_1_0  0x0301
#define TLS_VERSION_1_1  0x0302
#define TLS_VERSION_1_2  0x0303
#define TLS_VERSION_1_3  0x0304

/* TLS Record Header */
struct tls_record {
    uint8_t  content_type;
    uint16_t version;
    uint16_t length;
} __attribute__((packed));

/* TLS Handshake Header */
struct tls_handshake {
    uint8_t  msg_type;
    uint8_t  length[3];
} __attribute__((packed));

/* JA4 Extension types */
#define JA4_EXT_SERVER_NAME            0x0000
#define JA4_EXT_MAX_FRAGMENT_LENGTH   0x0001
#define JA4_EXT_STATUS_REQUEST        0x0005
#define JA4_EXT_SUPPORTED_GROUPS      0x000a
#define JA4_EXT_EC_POINT_FORMATS      0x000b
#define JA4_EXT_SIGNATURE_ALGORITHMS  0x000d
#define JA4_EXT_APPLICATION_LAYER_PRT 0x0010
#define JA4_EXT_SUPPORTED_VERSIONS    0x002b
#define JA4_EXT_COOKIE               0x002c
#define JA4_EXT_PADDING              0x0015
#define JA4_EXT_SESSION_TICKET        0x0023
#define JA4_EXT_PRE_SHARED_KEY        0x0029
#define JA4_EXT_EARLY_DATA            0x002a
#define JA4_EXT_KEY_SHARE              0x0033

/* TLS Cipher Suite IDs */
#define TLS_CIPHER_AES_128_GCM_SHA256              0x1301
#define TLS_CIPHER_AES_256_GCM_SHA384              0x1302
#define TLS_CIPHER_CHACHA20_POLY1305_SHA256        0x1303
#define TLS_CIPHER_AES_128_CCM_SHA256              0x1304
#define TLS_CIPHER_AES_128_CCM_8_SHA256            0x1305
#define TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256    0xc02b
#define TLS_CIPHER_ECDHE_RSA_AES_256_GCM_SHA384    0xc02c
#define TLS_CIPHER_ECDHE_RSA_CHACHA20_POLY1305     0xcca8
#define TLS_CIPHER_RSA_AES_128_GCM_SHA256         0x009c
#define TLS_CIPHER_RSA_AES_256_GCM_SHA384         0x009d

/* Parsed TLS information */
struct tls_info {
    uint8_t  handshake_type;
    uint16_t tls_version;
    bool valid;
    /* JA4 fingerprint fields */
    uint16_t ja4_ciphers[2];     /* First 2 cipher suites */
    uint16_t ja4_ext_count;      /* Number of extensions */
    uint8_t  ja4_extensions[16]; /* Extension type bitmap */
    char     ja4_sni[256];       /* SNI hostname */
    char     ja4_alpn[16];       /* ALPN protocol */
    char     ja4_fingerprint[64]; /* Complete JA4 fingerprint */
};

/* Parse TLS record */
int tls_record_parse(const uint8_t *packet, size_t len, struct tls_info *info);

/* Generate JA4 fingerprint */
void tls_generate_ja4_fingerprint(struct tls_info *info);

/* Get TLS version string */
const char *tls_version_to_str(uint16_t version);

/* Get TLS handshake type string */
const char *tls_hs_type_to_str(uint8_t type);

/* Get TLS record type string */
const char *tls_record_type_to_str(uint8_t type);

/* Get JA4 fingerprint */
static inline const char *tls_ja4_fingerprint(const struct tls_info *info)
{
    return info->ja4_fingerprint;
}

#endif /* TLS_H */