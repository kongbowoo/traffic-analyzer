#ifndef CONFIG_H
#define CONFIG_H

/* Default configuration values */
#define DEFAULT_FLOW_TABLE_SIZE    1024
#define DEFAULT_IP_TABLE_SIZE      1024
#define DEFAULT_JA4_TABLE_SIZE     1024
#define DEFAULT_DISPLAY_INTERVAL   1  /* seconds */
#define DEFAULT_TOP_N              5

/* Buffer sizes */
#define MAX_IP_STR_LEN             16
#define MAX_COUNTRY_CODE_LEN       4
#define MAX_FINGERPRINT_LEN        64
#define MAX_DOMAIN_LEN             256
#define MAX_ALPN_LEN               16

/* Protocol IDs */
#define PROTOCOL_ICMP              1
#define PROTOCOL_TCP               6
#define PROTOCOL_UDP               17

/* Application protocol IDs */
#define APP_PROTO_HTTP             1
#define APP_PROTO_HTTPS            2
#define APP_PROTO_DNS              3
#define APP_PROTO_ICMP             4
#define APP_PROTO_UNKNOWN          0

/* Well-known ports */
#define PORT_HTTP                  80
#define PORT_HTTPS                 443
#define PORT_DNS                   53

#endif /* CONFIG_H */