#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "packet_parser.h"
#include "stats_collector.h"
#include "display.h"

#define BUFFER_SIZE 65536

/* Global statistics collector */
static struct stats_collector *g_collector = NULL;
static volatile int g_running = 1;

/* Signal handler for graceful shutdown */
static void signal_handler(int signum)
{
    (void)signum;
    g_running = 0;
}

/* Capture using raw socket (WSL2 compatible without libpcap) */
static int capture_raw_socket(const char *interface)
{
    int sock_fd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    uint8_t buffer[BUFFER_SIZE];
    ssize_t len;
    struct packet_info info;

    /* Create raw socket */
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        close(sock_fd);
        return -1;
    }

    /* Bind to interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Failed to bind to interface");
        close(sock_fd);
        return -1;
    }

    /* Set socket to non-blocking */
    int flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    printf("Capturing on interface: %s\n", interface);

    /* Capture loop */
    time_t last_display = time(NULL);

    while (g_running) {
        /* Try to receive a packet */
        len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (len > 0) {
            /* Parse the packet */
            if (parse_packet(buffer, len, &info) == 0) {
                /* Update statistics */
                stats_collector_process(g_collector, &info, len);
            }
        } else {
            /* No packet available, sleep a bit */
            usleep(1000);  /* 1ms */
        }

        /* Update display every second */
        time_t now = time(NULL);
        if (now - last_display >= 1) {
            stats_collector_snapshot(g_collector);
            display_stats(g_collector);
            last_display = now;
        }
    }

    close(sock_fd);
    return 0;
}

/* Print usage */
static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -i <interface>  Network interface to capture from (default: eth0)\n");
    printf("  -s <size>       Flow table size (default: 1024)\n");
    printf("  -h              Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -i eth0\n", prog_name);
}

int main(int argc, char *argv[])
{
    const char *interface = "eth0";
    uint32_t flow_table_size = 1024;
    int ret = 0;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            flow_table_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize statistics collector */
    g_collector = stats_collector_init(flow_table_size);
    if (!g_collector) {
        fprintf(stderr, "Error: Failed to initialize statistics collector\n");
        return 1;
    }

    /* Initialize display */
    display_init();

    printf("Starting traffic analyzer...\n");

    /* Start capture */
    if (capture_raw_socket(interface) < 0) {
        ret = 1;
    }

    /* Cleanup */
    printf("\nShutting down...\n");
    stats_collector_destroy(g_collector);

    return ret;
}