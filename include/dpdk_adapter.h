#ifndef DPDK_ADAPTER_H
#define DPDK_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* Default configuration */
#define DPDK_MBUF_SIZE          (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define DPDK_MBUF_CACHE_SIZE    32
#define DPDK_NUM_MBUFS          8191
#define DPDK_BURST_SIZE         32
#define DPDK_RX_RING_SIZE       512
#define DPDK_TX_RING_SIZE       512

/* DPDK context */
struct dpdk_context {
    uint16_t port_id;                /* DPDK port ID */
    struct rte_mempool *mbuf_pool;   /* Memory pool for mbufs */
    uint16_t nb_rx_queues;           /* Number of RX queues */
    uint16_t nb_tx_queues;           /* Number of TX queues */
    char port_name[RTE_ETH_NAME_MAX_LEN];
    bool initialized;
};

/* Port configuration */
struct dpdk_port_config {
    const char *port_name;
    uint16_t nb_rx_queues;
    uint16_t nb_tx_queues;
    uint16_t rx_ring_size;
    uint16_t tx_ring_size;
    uint32_t num_mbufs;
};

/* Initialize DPDK environment and context */
int dpdk_init(struct dpdk_context *ctx, const struct dpdk_port_config *config);

/* Cleanup DPDK resources */
void dpdk_cleanup(struct dpdk_context *ctx);

/* Receive burst of packets */
uint16_t dpdk_rx_burst(struct dpdk_context *ctx,
                        struct rte_mbuf **pkts,
                        uint16_t nb_pkts,
                        uint16_t queue_id);

/* Transmit burst of packets */
uint16_t dpdk_tx_burst(struct dpdk_context *ctx,
                        struct rte_mbuf **pkts,
                        uint16_t nb_pkts,
                        uint16_t queue_id);

/* Get packet data pointer */
static inline void *dpdk_pkt_data(struct rte_mbuf *mbuf)
{
    return rte_pktmbuf_mtod(mbuf, void *);
}

/* Get packet length */
static inline uint16_t dpdk_pkt_len(struct rte_mbuf *mbuf)
{
    return rte_pktmbuf_pkt_len(mbuf);
}

/* Free packet */
static inline void dpdk_pkt_free(struct rte_mbuf *mbuf)
{
    rte_pktmbuf_free(mbuf);
}

/* Ref count increment */
static inline void dpdk_pkt_ref(struct rte_mbuf *mbuf)
{
    rte_pktmbuf_refcnt_update(mbuf, 1);
}

/* Check if DPDK is initialized */
bool dpdk_is_initialized(const struct dpdk_context *ctx);

/* Get port MAC address */
int dpdk_get_mac_addr(struct dpdk_context *ctx, struct rte_ether_addr *mac_addr);

/* Get port MTU */
int dpdk_get_mtu(struct dpdk_context *ctx, uint16_t *mtu);

/* Set promiscuous mode */
int dpdk_set_promiscuous(struct dpdk_context *ctx, bool enable);

/* Print port statistics */
void dpdk_print_stats(struct dpdk_context *ctx);

/* Reset port statistics */
void dpdk_reset_stats(struct dpdk_context *ctx);

#endif /* DPDK_ADAPTER_H */