/* Feature test macros - must be before any includes */
#ifndef USE_DPDK
    #define _DEFAULT_SOURCE
    #define _BSD_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifdef USE_DPDK
    #include <rte_eal.h>
    #include <rte_lcore.h>
    #include <rte_launch.h>
    #include <rte_debug.h>
    #include <rte_cycles.h>

    #include "dpdk_adapter.h"
    #define DPDK_MODE 1
#else
    #define DPDK_MODE 0
    /* Non-DPDK mode - use libpcap for packet capture */
    #include <pcap.h>
#endif

#include "packet_parser.h"
#include "stats_collector.h"
#include "display/renderer.h"
#include "../analyzer/geolocation.h"

/* Global state */
static volatile int g_running = 1;
static struct stats_collector *g_collector = NULL;
static struct renderer *g_renderer = NULL;

/* Signal handler */
static void signal_handler(int signum)
{
    (void)signum;
    g_running = 0;
}

#ifdef USE_DPDK
/* Worker thread function for DPDK */
static int packet_processor(void *arg)
{
    struct dpdk_context *dpdk_ctx = (struct dpdk_context *)arg;
    struct rte_mbuf *pkts[DPDK_BURST_SIZE];
    struct packet_info info;

    printf("Worker thread started on core %u\n", rte_lcore_id());

    time_t last_display = time(NULL);

    while (g_running) {
        /* Receive burst of packets */
        uint16_t nb_rx = dpdk_rx_burst(dpdk_ctx, pkts, DPDK_BURST_SIZE, 0);

        /* Process each packet */
        for (uint16_t i = 0; i < nb_rx; i++) {
            if (packet_parse_mbuf(pkts[i], &info) == 0 && info.valid) {
                stats_collector_process(g_collector, &info, info.total_len);
            }

            /* Free the packet */
            dpdk_pkt_free(pkts[i]);
        }

        /* Update display every second */
        time_t now = time(NULL);
        if (now - last_display >= 1) {
            stats_collector_snapshot(g_collector);

            const struct stats_snapshot *snapshot = stats_collector_get_snapshot(g_collector);
            const struct geo_db *geo_db = stats_collector_get_geo_db(g_collector);
            if (snapshot && g_renderer) {
                renderer_render_all(g_renderer,
                                    &snapshot->stats,
                                    snapshot->bandwidth,
                                    (struct flow_entry **)snapshot->top_flows,
                                    (struct ip_entry **)snapshot->top_src_ips,
                                    (struct ip_entry **)snapshot->top_dst_ips,
                                    (struct fingerprint_entry **)snapshot->top_fingerprints,
                                    geo_db);
            }

            last_display = now;
        }

        /* Small sleep to prevent busy loop */
        if (nb_rx == 0) {
            usleep(1000);
        }
    }

    printf("Worker thread exiting on core %u\n", rte_lcore_id());
    return 0;
}
#else
/* Packet capture using libpcap (non-DPDK mode) */
static int raw_socket_receive(const char *interface, struct stats_collector *collector)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *packet;
    struct packet_info info;
    time_t last_display = time(NULL);
    int ret;

    /* Open the device for packet capture */
    handle = pcap_open_live(interface, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return -1;
    }

    printf("Listening on interface %s (non-DPDK mode using libpcap)...\n", interface);
    printf("Press Ctrl+C to stop\n\n");

    while (g_running) {
        /* Read a packet with timeout (1000ms) */
        ret = pcap_next_ex(handle, &header, &packet);

        if (ret == 0) {
            /* Timeout - check if we need to update display */
            time_t now = time(NULL);
            if (now - last_display >= 1) {
                stats_collector_snapshot(collector);

                const struct stats_snapshot *snapshot = stats_collector_get_snapshot(collector);
                const struct geo_db *geo_db = stats_collector_get_geo_db(collector);
                if (snapshot && g_renderer) {
                    renderer_render_all(g_renderer,
                                        &snapshot->stats,
                                        snapshot->bandwidth,
                                        (struct flow_entry **)snapshot->top_flows,
                                        (struct ip_entry **)snapshot->top_src_ips,
                                        (struct ip_entry **)snapshot->top_dst_ips,
                                        (struct fingerprint_entry **)snapshot->top_fingerprints,
                                        geo_db);
                }

                last_display = now;
            }
            continue;
        }

        if (ret < 0) {
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            break;
        }

        /* Parse the packet */
        if (packet_parse_buffer(packet, header->caplen, &info) == 0 && info.valid) {
            stats_collector_process(collector, &info, info.total_len);
        }

        /* Update display every second */
        time_t now = time(NULL);
        if (now - last_display >= 1) {
            stats_collector_snapshot(collector);

            const struct stats_snapshot *snapshot = stats_collector_get_snapshot(collector);
            const struct geo_db *geo_db = stats_collector_get_geo_db(collector);
            if (snapshot && g_renderer) {
                renderer_render_all(g_renderer,
                                    &snapshot->stats,
                                    snapshot->bandwidth,
                                    (struct flow_entry **)snapshot->top_flows,
                                    (struct ip_entry **)snapshot->top_src_ips,
                                    (struct ip_entry **)snapshot->top_dst_ips,
                                    (struct fingerprint_entry **)snapshot->top_fingerprints,
                                    geo_db);
            }

            last_display = now;
        }
    }

    /* Close the capture handle */
    pcap_close(handle);
    return 0;
}
#endif

/* Print usage */
static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
#ifdef USE_DPDK
    printf("DPDK Mode:\n");
    printf("  [EAL options] -- [APP options]\n");
    printf("\nEAL options:\n");
    printf("  -c COREMASK      Hexadecimal bitmask of cores to run on\n");
    printf("  -n NUM           Number of memory channels\n");
    printf("  --file-prefix    Prefix for hugepage files\n");
    printf("\nAPP options:\n");
    printf("  --port NAME      DPDK port name (default: 0000:00:01.0)\n");
    printf("  --queues N       Number of RX/TX queues (default: 1)\n");
    printf("  --ring-size N    RX/TX ring size (default: 512)\n");
#else
    printf("Non-DPDK Mode (raw socket):\n");
    printf("  -i INTERFACE     Network interface to capture from\n");
#endif
    printf("  --help          Show this help message\n");
    printf("\nExamples:\n");
#ifdef USE_DPDK
    printf("  %s -c 0x3 -n 4 -- --port 0000:00:01.0\n", prog_name);
#else
    printf("  %s -i eth0\n", prog_name);
#endif
}

int main(int argc, char *argv[])
{
    int ret = 0;

#ifdef USE_DPDK
    /* Parse application arguments */
    const char *port_name = "0000:00:01.0";
    uint16_t nb_queues = 1;
    uint16_t ring_size = 512;

    /* Find "--" separator */
    int app_argc = 0;
    char **app_argv = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            app_argc = argc - i - 1;
            app_argv = &argv[i + 1];
            break;
        }
    }

    /* Parse app arguments */
    if (app_argv) {
        for (int i = 0; i < app_argc; i++) {
            if (strcmp(app_argv[i], "--port") == 0 && i + 1 < app_argc) {
                port_name = app_argv[++i];
            } else if (strcmp(app_argv[i], "--queues") == 0 && i + 1 < app_argc) {
                nb_queues = atoi(app_argv[++i]);
            } else if (strcmp(app_argv[i], "--ring-size") == 0 && i + 1 < app_argc) {
                ring_size = atoi(app_argv[++i]);
            } else if (strcmp(app_argv[i], "--help") == 0 || strcmp(app_argv[i], "-h") == 0) {
                print_usage(argv[0]);
                return 0;
            }
        }
    }

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Cannot initialize EAL\n");
    }

    printf("EAL initialized with %u cores\n", rte_lcore_count());

    /* Check available lcores */
    unsigned main_lcore = rte_get_main_lcore();
    unsigned worker_lcore = RTE_MAX_LCORE;

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        worker_lcore = lcore;
        break;
    }

    if (worker_lcore >= RTE_MAX_LCORE) {
        rte_exit(EXIT_FAILURE, "No available worker lcore\n");
    }

    printf("Main lcore: %u, Worker lcore: %u\n", main_lcore, worker_lcore);

    /* Initialize DPDK context */
    struct dpdk_context dpdk_ctx;
    struct dpdk_port_config port_cfg = {
        .port_name = port_name,
        .nb_rx_queues = nb_queues,
        .nb_tx_queues = nb_queues,
        .rx_ring_size = ring_size,
        .tx_ring_size = ring_size,
        .num_mbufs = DPDK_NUM_MBUFS
    };

    if (dpdk_init(&dpdk_ctx, &port_cfg) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to initialize DPDK\n");
    }

    printf("Starting traffic analyzer on port %s...\n", port_name);
#else
    /* Parse non-DPDK arguments */
    const char *interface = "eth0";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    printf("Starting traffic analyzer on interface %s (non-DPDK mode)...\n", interface);
#endif

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize statistics collector */
    struct stats_config stats_cfg = {
        .flow_table_size = 1024,
        .ip_table_size = 1024,
        .fingerprint_table_size = 1024,
        .enable_geo = true
    };

    g_collector = stats_collector_init(&stats_cfg);
    if (!g_collector) {
        fprintf(stderr, "Failed to initialize statistics collector\n");
        return EXIT_FAILURE;
    }

    /* Initialize renderer */
    g_renderer = renderer_console_create();
    if (!g_renderer) {
        fprintf(stderr, "Failed to initialize renderer\n");
        stats_collector_destroy(g_collector);
        return EXIT_FAILURE;
    }

    if (g_renderer->init) {
        g_renderer->init(g_renderer);
    }

#ifdef USE_DPDK
    /* Launch worker on slave core */
    rte_eal_remote_launch(packet_processor, &dpdk_ctx, worker_lcore);

    /* Main loop - just wait for signal */
    while (g_running) {
        sleep(1);
    }

    /* Wait for worker to finish */
    rte_eal_wait_lcore(worker_lcore);

    /* Cleanup DPDK */
    dpdk_cleanup(&dpdk_ctx);
    rte_eal_cleanup();
#else
    /* Run raw socket receiver */
    raw_socket_receive(interface, g_collector);
#endif

    /* Cleanup */
    printf("\nShutting down...\n");

    if (g_renderer->cleanup) {
        g_renderer->cleanup(g_renderer);
    }
    renderer_destroy(g_renderer);

    stats_collector_destroy(g_collector);

    return ret;
}