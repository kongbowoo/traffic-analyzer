#include "dpdk_init.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <stdio.h>
#include <string.h>

static struct dpdk_context *global_ctx = NULL;

/* Initialize DPDK EAL */
int dpdk_eal_init(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Error: EAL initialization failed\n");
        return -1;
    }

    return ret;
}

/* Initialize DPDK port */
int dpdk_port_init(struct dpdk_context *ctx, uint16_t port_id, uint16_t rx_queue)
{
    struct rte_eth_conf port_conf;
    struct rte_mempool *mbuf_pool;
    uint16_t nb_rxd = RX_RING_SIZE;
    int ret;
    struct rte_eth_dev_info dev_info;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    /* Get device info */
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        fprintf(stderr, "Error: Cannot get device info for port %u\n", port_id);
        return -1;
    }

    /* Create mbuf pool */
    char pool_name[64];
    snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%u", port_id);
    mbuf_pool = rte_pktmbuf_pool_create(pool_name, NUM_MBUFS * MAX_PORTS,
                                         MBUF_CACHE_SIZE, 0,
                                         RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        fprintf(stderr, "Error: Cannot create mbuf pool\n");
        return -1;
    }

    /* Configure the Ethernet device */
    ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
    if (ret != 0) {
        fprintf(stderr, "Error: Cannot configure port %u\n", port_id);
        return -1;
    }

    /* Setup RX queue */
    ret = rte_eth_rx_queue_setup(port_id, rx_queue, nb_rxd,
                                  rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    if (ret < 0) {
        fprintf(stderr, "Error: RX queue setup failed for port %u\n", port_id);
        return -1;
    }

    /* Start the Ethernet port */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        fprintf(stderr, "Error: Cannot start port %u\n", port_id);
        return -1;
    }

    /* Enable promiscuous mode */
    rte_eth_promiscuous_enable(port_id);

    /* Save context */
    ctx->port_id = port_id;
    ctx->rx_queue = rx_queue;
    ctx->nb_rx_ports = 1;
    ctx->nb_rxd = nb_rxd;
    global_ctx = ctx;

    printf("Port %u: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           port_id,
           dev_info.mac_addr.addr_bytes[0],
           dev_info.mac_addr.addr_bytes[1],
           dev_info.mac_addr.addr_bytes[2],
           dev_info.mac_addr.addr_bytes[3],
           dev_info.mac_addr.addr_bytes[4],
           dev_info.mac_addr.addr_bytes[5]);

    return 0;
}

/* Receive packets */
uint16_t dpdk_rx_burst(struct dpdk_context *ctx, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    if (!ctx) {
        return 0;
    }

    return rte_eth_rx_burst(ctx->port_id, ctx->rx_queue, pkts, nb_pkts);
}

/* Free packets */
void dpdk_free_pkts(struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    rte_pktmbuf_free_bulk(pkts, nb_pkts);
}

/* Cleanup DPDK */
void dpdk_cleanup(struct dpdk_context *ctx)
{
    if (!ctx) {
        return;
    }

    rte_eth_dev_stop(ctx->port_id);
    rte_eth_dev_close(ctx->port_id);
    global_ctx = NULL;
}