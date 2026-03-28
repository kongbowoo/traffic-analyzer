#ifndef DPDK_INIT_H
#define DPDK_INIT_H

#include <stdint.h>

#define RX_RING_SIZE 512
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_PORTS 1

/* DPDK context */
struct dpdk_context {
    uint8_t port_id;
    uint16_t rx_queue;
    uint16_t nb_rx_ports;
    uint16_t nb_rxd;
};

/* Initialize DPDK EAL */
int dpdk_eal_init(int argc, char **argv);

/* Initialize DPDK port */
int dpdk_port_init(struct dpdk_context *ctx, uint16_t port_id, uint16_t rx_queue);

/* Receive packets */
uint16_t dpdk_rx_burst(struct dpdk_context *ctx, struct rte_mbuf **pkts, uint16_t nb_pkts);

/* Free packets */
void dpdk_free_pkts(struct rte_mbuf **pkts, uint16_t nb_pkts);

/* Cleanup DPDK */
void dpdk_cleanup(struct dpdk_context *ctx);

#endif /* DPDK_INIT_H */