#include "tls.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

/* Parse TLS ClientHello for JA4 fingerprint */
static void parse_tls_clienthello(const uint8_t *payload, size_t len,
                                   struct tls_info *info)
{
    const uint8_t *ptr = payload;
    size_t remaining = len;

    /* Skip handshake header (4 bytes) */
    if (remaining < 4) return;
    ptr += 4;
    remaining -= 4;

    /* Skip TLS version (2 bytes) */
    if (remaining < 2) return;
    ptr += 2;
    remaining -= 2;

    /* Skip Random (32 bytes) */
    if (remaining < 32) return;
    ptr += 32;
    remaining -= 32;

    /* Skip Session ID */
    if (remaining < 1) return;
    uint8_t sid_len = *ptr++;
    remaining--;
    if (remaining < sid_len) return;
    ptr += sid_len;
    remaining -= sid_len;

    /* Parse Cipher Suites */
    if (remaining < 2) return;
    uint16_t cipher_len = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    remaining -= 2;

    if (remaining >= cipher_len) {
        uint16_t cipher_count = cipher_len / 2;
        for (int i = 0; i < (int)cipher_count && i < 2; i++) {
            info->ja4_ciphers[i] = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            remaining -= 2;
        }
        ptr += (cipher_len - (cipher_count > 2 ? 4 : cipher_count * 2));
        remaining -= (cipher_len - (cipher_count > 2 ? 4 : cipher_count * 2));
    }

    /* Skip Compression Methods */
    if (remaining < 1) return;
    uint8_t comp_len = *ptr++;
    remaining--;
    if (remaining < comp_len) return;
    ptr += comp_len;
    remaining -= comp_len;

    /* Parse Extensions */
    if (remaining < 2) return;
    uint16_t ext_len = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    remaining -= 2;

    if (remaining < ext_len) return;

    uint8_t ext_count = 0;
    uint32_t ext_parsed = 0;

    while (ext_parsed < ext_len && remaining >= 4) {
        uint16_t ext_type = ntohs(*(uint16_t *)ptr);
        uint16_t ext_data_len = ntohs(*(uint16_t *)(ptr + 2));
        ptr += 4;
        remaining -= 4;
        ext_parsed += 4;

        /* Track extensions */
        if (ext_type <= 0x003f) {
            info->ja4_extensions[ext_type / 8] |= (1 << (ext_type % 8));
        }

        /* Parse SNI */
        if (ext_type == JA4_EXT_SERVER_NAME && ext_data_len >= 2 && remaining >= 2) {
            uint16_t sni_list_len = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            remaining -= 2;
            ext_parsed += 2;

            if (sni_list_len >= 3 && remaining >= 3) {
                uint8_t sni_type = *ptr++;
                remaining--;
                ext_parsed++;

                if (sni_type == 0 && remaining >= 2) {
                    uint16_t sni_len = ntohs(*(uint16_t *)ptr);
                    ptr += 2;
                    remaining -= 2;
                    ext_parsed += 2;

                    if (sni_len > 0 && remaining >= sni_len) {
                        uint16_t copy_len = sni_len;
                        if (copy_len > sizeof(info->ja4_sni) - 1)
                            copy_len = sizeof(info->ja4_sni) - 1;
                        memcpy(info->ja4_sni, ptr, copy_len);
                        info->ja4_sni[copy_len] = '\0';
                        ptr += sni_len;
                        remaining -= sni_len;
                        ext_parsed += sni_len;
                    }
                }
            }
        } else if (ext_type == JA4_EXT_APPLICATION_LAYER_PRT && ext_data_len >= 2 && remaining >= 2) {
            /* Parse ALPN */
            uint16_t alpn_list_len = ntohs(*(uint16_t *)ptr);
            ptr += 2;
            remaining -= 2;
            ext_parsed += 2;

            if (alpn_list_len >= 1 && remaining >= 1) {
                uint8_t alpn_len = *ptr++;
                remaining--;
                ext_parsed++;

                if (alpn_len > 0 && remaining >= alpn_len) {
                    uint16_t copy_len = alpn_len;
                    if (copy_len > sizeof(info->ja4_alpn) - 1)
                        copy_len = sizeof(info->ja4_alpn) - 1;
                    memcpy(info->ja4_alpn, ptr, copy_len);
                    info->ja4_alpn[copy_len] = '\0';
                    ptr += ext_data_len;
                    remaining -= ext_data_len;
                    ext_parsed += ext_data_len;
                }
            }
        } else {
            if (ext_data_len <= remaining) {
                ptr += ext_data_len;
                remaining -= ext_data_len;
                ext_parsed += ext_data_len;
            } else {
                break;
            }
        }

        ext_count++;
        if (ext_count >= 255) break;
    }

    info->ja4_ext_count = ext_count;
    tls_generate_ja4_fingerprint(info);
}

/* Parse TLS record */
int tls_record_parse(const uint8_t *packet, size_t len, struct tls_info *info)
{
    memset(info, 0, sizeof(struct tls_info));

    if (len < sizeof(struct tls_record)) {
        return -1;
    }

    const struct tls_record *record = (const struct tls_record *)packet;

    if (record->content_type != TLS_TYPE_HANDSHAKE) {
        return -1;
    }

    uint16_t record_len = ntohs(record->length);
    if (len < sizeof(struct tls_record) + record_len) {
        return -1;
    }

    const struct tls_handshake *hs = (const struct tls_handshake *)(packet + sizeof(struct tls_record));
    info->handshake_type = hs->msg_type;
    info->tls_version = ntohs(record->version);

    if (info->handshake_type == TLS_HS_CLIENT_HELLO ||
        info->handshake_type == TLS_HS_SERVER_HELLO ||
        info->handshake_type == TLS_HS_CERTIFICATE) {
        info->valid = true;

        if (info->handshake_type == TLS_HS_CLIENT_HELLO) {
            parse_tls_clienthello(packet, len, info);
        }

        return 0;
    }

    return -1;
}

/* Generate JA4 fingerprint */
void tls_generate_ja4_fingerprint(struct tls_info *info)
{
    char version_code[8];
    switch (info->tls_version) {
        case TLS_VERSION_1_0: strcpy(version_code, "t10d"); break;
        case TLS_VERSION_1_1: strcpy(version_code, "t11d"); break;
        case TLS_VERSION_1_2: strcpy(version_code, "t12d"); break;
        case TLS_VERSION_1_3: strcpy(version_code, "t13d"); break;
        default: strcpy(version_code, "t??d"); break;
    }

    char ciphers_hex[8];
    if (info->ja4_ciphers[0] != 0) {
        snprintf(ciphers_hex, sizeof(ciphers_hex), "%04x", info->ja4_ciphers[0]);
        if (info->ja4_ciphers[1] != 0) {
            snprintf(ciphers_hex + 4, 4, "%04x", info->ja4_ciphers[1]);
        }
    } else {
        strcpy(ciphers_hex, "????");
    }

    char ext_count[8];
    snprintf(ext_count, sizeof(ext_count), "%02x", (unsigned int)info->ja4_ext_count);

    if (strlen(info->ja4_alpn) > 0) {
        snprintf(info->ja4_fingerprint, sizeof(info->ja4_fingerprint),
                 "%s%s%s_%s", version_code, ciphers_hex, ext_count, info->ja4_alpn);
    } else {
        snprintf(info->ja4_fingerprint, sizeof(info->ja4_fingerprint),
                 "%s%s%s", version_code, ciphers_hex, ext_count);
    }
}

/* Get TLS version string */
const char *tls_version_to_str(uint16_t version)
{
    switch (version) {
        case TLS_VERSION_1_0: return "TLS 1.0";
        case TLS_VERSION_1_1: return "TLS 1.1";
        case TLS_VERSION_1_2: return "TLS 1.2";
        case TLS_VERSION_1_3: return "TLS 1.3";
        default: return "Unknown";
    }
}

/* Get TLS handshake type string */
const char *tls_hs_type_to_str(uint8_t type)
{
    switch (type) {
        case TLS_HS_CLIENT_HELLO: return "ClientHello";
        case TLS_HS_SERVER_HELLO: return "ServerHello";
        case TLS_HS_CERTIFICATE: return "Certificate";
        case TLS_HS_SERVER_KEY_EXCH: return "ServerKeyExchange";
        case TLS_HS_SERVER_HELLO_DONE: return "ServerHelloDone";
        default: return "Unknown";
    }
}

/* Get TLS record type string */
const char *tls_record_type_to_str(uint8_t type)
{
    switch (type) {
        case TLS_TYPE_CHANGE_CIPHER_SPEC: return "ChangeCipherSpec";
        case TLS_TYPE_ALERT: return "Alert";
        case TLS_TYPE_HANDSHAKE: return "Handshake";
        case TLS_TYPE_APPLICATION_DATA: return "ApplicationData";
        default: return "Unknown";
    }
}