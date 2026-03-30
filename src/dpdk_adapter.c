#include "dpdk_adapter.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_ethdev.h>

/* Ethernet configuration */
static const struct rte_eth_conf eth_conf = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .split_hdr_size = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

/* Initialize DPDK environment and context */
int dpdk_init(struct dpdk_context *ctx, const struct dpdk_port_config *config)
{
    if (!ctx || !config) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }

    memset(ctx, 0, sizeof(struct dpdk_context));
    ctx->nb_rx_queues = config->nb_rx_queues;
    ctx->nb_tx_queues = config->nb_tx_queues;
    strncpy(ctx->port_name, config->port_name, RTE_ETH_NAME_MAX_LEN - 1);

    /* Find the port */
    uint16_t port_id = 0;
    RTE_ETH_FOREACH_DEV(port_id) {
        char name[RTE_ETH_NAME_MAX_LEN];
        rte_eth_dev_get_name_by_port(port_id, name);

        if (strcmp(name, config->port_name) == 0) {
            ctx->port_id = port_id;
            break;
        }
    }

    if (ctx->port_id == 0) {
        /* Use first port if not found */
        RTE_ETH_FOREACH_DEV(port_id) {
            ctx->port_id = port_id;
            break;
        }
    }

    if (ctx->port_id == 0 && !rte_eth_dev_is_valid_port(ctx->port_id)) {
        fprintf(stderr, "No valid DPDK port found\n");
        return -1;
    }

    /* Create mbuf pool */
    char pool_name[64];
    snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%u", ctx->port_id);

    ctx->mbuf_pool = rte_pktmbuf_pool_create(
        pool_name,
        config->num_mbufs,
        DPDK_MBUF_CACHE_SIZE,
        0,
        DPDK_MBUF_SIZE,
        rte_socket_id()
    );

    if (!ctx->mbuf_pool) {
        fprintf(stderr, "Failed to create mbuf pool\n");
        return -1;
    }

    /* Configure the port */
    struct rte_eth_conf port_conf = eth_conf;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;

    memset(&rx_conf, 0, sizeof(rx_conf));
    rx_conf.rx_thresh.pthresh = 8;
    rx_conf.rx_thresh.hthresh = 4;
    rx_conf.rx_thresh.wthresh = 4;
    rx_conf.rx_free_thresh = 32;

    memset(&tx_conf, 0, sizeof(tx_conf));
    tx_conf.tx_thresh.pthresh = 32;
    tx_conf.tx_thresh.hthresh = 0;
    tx_conf.tx_thresh.wthresh = 0;
    tx_conf.tx_free_thresh = 32;

    int ret = rte_eth_dev_configure(ctx->port_id,
                                     config->nb_rx_queues,
                                     config->nb_tx_queues,
                                     &port_conf);
    if (ret < 0) {
        fprintf(stderr, "Failed to configure port %u: %s\n",
                ctx->port_id, rte_strerror(-ret));
        return -1;
    }

    /* Setup RX queues */
    for (uint16_t q = 0; q < config->nb_rx_queues; q++) {
        ret = rte_eth_rx_queue_setup(ctx->port_id, q,
                                      config->rx_ring_size,
                                      rte_socket_id(),
                                      &rx_conf,
                                      ctx->mbuf_pool);
        if (ret < 0) {
            fprintf(stderr, "Failed to setup RX queue %u: %s\n",
                    q, rte_strerror(-ret));
            return -1;
        }
    }

    /* Setup TX queues */
    for (uint16_t q = 0; q < config->nb_tx_queues; q++) {
        ret = rte_eth_tx_queue_setup(ctx->port_id, q,
                                      config->tx_ring_size,
                                      rte_socket_id(),
                                      &tx_conf);
        if (ret < 0) {
            fprintf(stderr, "Failed to setup TX queue %u: %s\n",
                    q, rte_strerror(-ret));
            return -1;
        }
    }

    /* Start the port */
    ret = rte_eth_dev_start(ctx->port_id);
    if (ret < 0) {
        fprintf(stderr, "Failed to start port %u: %s\n",
                ctx->port_id, rte_strerror(-ret));
        return -1;
    }

    /* Set promiscuous mode */
    rte_eth_promiscuous_enable(ctx->port_id);

    ctx->initialized = true;

    printf("DPDK initialized successfully on port %u (%s)\n",
           ctx->port_id, ctx->port_name);

    return 0;
}

/* Cleanup DPDK resources */
void dpdk_cleanup(struct dpdk_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->initialized && ctx->port_id != 0) {
        rte_eth_dev_stop(ctx->port_id);
    }

    ctx->initialized = false;
}

/* Receive burst of packets */
uint16_t dpdk_rx_burst(struct dpdk_context *ctx,
                        struct rte_mbuf **pkts,
                        uint16_t nb_pkts,
                        uint16_t queue_id)
{
    if (!ctx || !ctx->initialized) {
        return 0;
    }

    if (queue_id >= ctx->nb_rx_queues) {
        return 0;
    }

    return rte_eth_rx_burst(ctx->port_id, queue_id, pkts, nb_pkts);
}

/* Transmit burst of packets */
uint16_t dpdk_tx_burst(struct dpdk_context *ctx,
                        struct rte_mbuf **pkts,
                        uint16_t nb_pkts,
                        uint16_t queue_id)
{
    if (!ctx || !ctx->initialized) {
        return 0;
    }

    if (queue_id >= ctx->nb_tx_queues) {
        return 0;
    }

    return rte_eth_tx_burst(ctx->port_id, queue_id, pkts, nb_pkts);
}

/* Check if DPDK is initialized */
bool dpdk_is_initialized(const struct dpdk_context *ctx)
{
    return ctx ? ctx->initialized : false;
}

/* Get port MAC address */
int dpdk_get_mac_addr(struct dpdk_context *ctx, struct rte_ether_addr *mac_addr)
{
    if (!ctx || !ctx->initialized || !mac_addr) {
        return -1;
    }

    return rte_eth_macaddr_get(ctx->port_id, mac_addr);
}

/* Get port MTU */
int dpdk_get_mtu(struct dpdk_context *ctx, uint16_t *mtu)
{
    if (!ctx || !ctx->initialized || !mtu) {
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(ctx->port_id, &dev_info);
    *mtu = dev_info.mtu;

    return 0;
}

/* Set promiscuous mode */
int dpdk_set_promiscuous(struct dpdk_context *ctx, bool enable)
{
    if (!ctx || !ctx->initialized) {
        return -1;
    }

    if (enable) {
        rte_eth_promiscuous_enable(ctx->port_id);
    } else {
        rte_eth_promiscuous_disable(ctx->port_id);
    }

    return 0;
}

/* Print port statistics */
void dpdk_print_stats(struct dpdk_context *ctx)
{
    if (!ctx || !ctx->initialized) {
        return;
    }

    struct rte_eth_stats stats;
    if (rte_eth_stats_get(ctx->port_id, &stats) == 0) {
        printf("\n=== Port %u Statistics ===\n", ctx->port_id);
        printf("  RX packets: %lu\n", stats.ipackets);
        printf("  RX bytes:   %lu\n", stats.ibytes);
        printf("  RX errors:  %lu\n", stats.ierrors);
        printf("  RX missed:  %lu\n", stats.imissed);
        printf("  TX packets: %lu\n", stats.opackets);
        printf("  TX bytes:   %lu\n", stats.obytes);
        printf("  TX errors:  %lu\n", stats.oerrors);
        printf("========================\n\n");
    }
}

/* Reset port statistics */
void dpdk_reset_stats(struct dpdk_context *ctx)
{
    if (!ctx || !ctx->initialized) {
        return;
    }

    rte_eth_stats_reset(ctx->port_id);
}