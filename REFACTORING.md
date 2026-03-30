# DPDK Traffic Analyzer - Modular Refactoring Summary

## Overview

This document summarizes the modular refactoring of the DPDK Traffic Analyzer with full DPDK integration.

## New Modular Architecture

### Directory Structure

```
dpdkDemo/
├── include/
│   ├── core/              # Core abstraction layer
│   │   ├── config.h       # Global configuration constants
│   │   ├── hash_table.h   # Generic hash table abstraction
│   │   └── types.h        # Generic types and utilities
│   │
│   ├── protocol/          # Protocol parsing modules
│   │   ├── ethernet.h     # Ethernet (using DPDK rte_ether.h)
│   │   ├── ip.h           # IPv4 (using DPDK rte_ip.h)
│   │   ├── tcp.h          # TCP (using DPDK rte_tcp.h)
│   │   ├── udp.h          # UDP (using DPDK rte_udp.h)
│   │   ├── icmp.h         # ICMP
│   │   ├── dns.h          # DNS parser
│   │   └── tls.h          # TLS parser with JA4 fingerprint
│   │
│   ├── analyzer/          # Traffic analysis modules
│   │   ├── flow_table.h   # Flow table (5-tuple tracking)
│   │   ├── ip_table.h     # Generic IP table (source/destination)
│   │   ├── fingerprint_table.h  # JA4 fingerprint table
│   │   └── geolocation.h  # IP geolocation lookup
│   │
│   ├── stats/             # Statistics modules
│   │   ├── counters.h     # Generic counter registry
│   │   └── traffic_stats.h # Traffic statistics
│   │
│   ├── display/           # Display/rendering modules
│   │   ├── formatter.h    # Formatting utilities
│   │   └── renderer.h     # Abstract renderer interface
│   │
│   ├── app/               # Application layer
│   │   ├── packet_parser.h    # Unified packet parsing interface
│   │   └── stats_collector.h  # Statistics collector
│   │
│   └── dpdk_adapter.h     # DPDK interface adapter
│
└── src/
    ├── core/              # Core implementations
    ├── protocol/          # Protocol implementations
    ├── analyzer/          # Analyzer implementations
    ├── stats/             # Statistics implementations
    ├── display/           # Display implementations
    ├── app/               # Application implementations
    └── dpdk_adapter.c     # DPDK adapter implementation
```

## DPDK Integration

### 1. Packet Reception (DPDK vs Raw Socket)

**Before (Raw Socket):**
```c
sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
```

**After (DPDK):**
```c
// DPDK PMD driver reception
struct rte_mbuf *pkts[DPDK_BURST_SIZE];
uint16_t nb_rx = dpdk_rx_burst(&dpdk_ctx, pkts, DPDK_BURST_SIZE, 0);

// Zero-copy packet processing
for (uint16_t i = 0; i < nb_rx; i++) {
    uint8_t *packet_data = rte_pktmbuf_mtod(pkts[i], uint8_t *);
    size_t packet_len = rte_pktmbuf_pkt_len(pkts[i]);
    // Process packet...
    rte_pktmbuf_free(pkts[i]);
}
```

### 2. Multi-Core Parallel Processing

```c
// EAL initialization with multiple cores
ret = rte_eal_init(argc, argv);

// Launch packet processor on slave core
unsigned worker_lcore;
RTE_LCORE_FOREACH_SLAVE(lcore) {
    worker_lcore = lcore;
    break;
}
rte_eal_remote_launch(packet_processor, &dpdk_ctx, worker_lcore);

// Main thread handles display/control
while (running) {
    sleep(1);
}
```

### 3. Memory Management (DPDK Memory Pools)

```c
// DPDK hugepage-backed memory pool
ctx->mbuf_pool = rte_pktmbuf_pool_create(
    "mbuf_pool",
    DPDK_NUM_MBUFS,      // Number of mbufs
    DPDK_MBUF_CACHE_SIZE, // Per-core cache
    0,
    DPDK_MBUF_SIZE,       // Size of each mbuf
    rte_socket_id()
);
```

### 4. Protocol Parsing (Using DPDK Structures)

```c
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

// Use DPDK structures directly
const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);
const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)(((uint8_t *)ip) + ip_hdr_len);

// Access fields directly (DPDK handles byte order)
uint16_t dst_port = tcp->dst_port;  // Already in network byte order
```

### 5. Statistics (DPDK Hardware Statistics)

```c
// Get hardware statistics from NIC
struct rte_eth_stats stats;
rte_eth_stats_get(port_id, &stats);

printf("RX packets: %lu\n", stats.ipackets);
printf("RX bytes: %lu\n", stats.ibytes);
printf("RX errors: %lu\n", stats.ierrors);
printf("TX packets: %lu\n", stats.opackets);
```

## Key DPDK Features Utilized

### PMD (Poll Mode Driver)
- Zero-copy packet reception
- Direct memory access to packets
- Hardware statistics

### EAL (Environment Abstraction Layer)
- Multi-core processing
- Hugepage memory management
- PCIe device discovery

### Memory Pools
- Efficient packet buffer allocation
- Per-core cache for performance
- Reference counting for packet sharing

### Ethernet Device API
- Multiple queue support
- Promiscuous mode control
- Link status monitoring

## Performance Benefits

1. **Zero-Copy**: Direct access to packet data from NIC DMA memory
2. **Batch Processing**: Process bursts of 32+ packets at once
3. **Multi-Core**: Dedicated core for packet processing
4. **Hugepages**: Reduce TLB misses, improve cache locality
5. **Poll Mode**: Eliminate interrupt overhead
6. **Hardware Offload**: Checksum/TCP segmentation offload

## Module Independence

### Core Module
- Generic hash table usable by any module
- Common utilities (buffer, types)
- No dependencies on other modules

### Protocol Module
- Each protocol is self-contained
- Uses DPDK structures when available
- Easy to add new protocols

### Analyzer Module
- Generic tables (flow, IP, fingerprint)
- Pluggable analysis components
- No protocol coupling

### Stats Module
- Counter registry for dynamic metrics
- Traffic statistics separate from collection
- Easy to extend with new metrics

### Display Module
- Abstract renderer interface
- Multiple output formats (console, JSON)
- Decoupled from statistics

### App Module
- Coordinates other modules
- Minimal business logic
- Easy to change application behavior

## Building and Running

### Prerequisites

1. DPDK installation (e.g., 22.11.1)
2. Hugepages configured
3. Network interface bound to DPDK driver (vfio-pci or uio_pci_generic)

### Build

```bash
make clean
make
```

### Run

```bash
# Basic run
sudo make run

# Or with custom parameters
sudo ./build/traffic_analyzer -c 0x3 -n 4 -- --port 0000:00:01.0

# Parameters:
# -c 0x3          : Use cores 0 and 1 (bitmask)
# -n 4            : 4 memory channels
# --port NAME     : DPDK port name
# --queues N      : Number of RX/TX queues
```

### Network Interface Setup

```bash
# Bind NIC to DPDK driver
sudo dpdk-devbind.py -b vfio-pci 0000:00:01.0

# Or use uio_pci_generic (for testing)
sudo dpdk-devbind.py -b uio_pci_generic 0000:00:01.0
```

## Extension Points

### Adding a New Protocol

1. Create `include/protocol/new_protocol.h`
2. Create `src/protocol/new_protocol.c`
3. Add to `packet_parser.c` detection logic
4. Add to `stats/traffic_stats.h` if needed

### Adding a New Analysis Module

1. Create `include/analyzer/new_module.h` using generic hash table
2. Implement in `src/analyzer/new_module.c`
3. Integrate with `stats_collector.c`

### Adding a New Output Format

1. Implement `renderer` interface in `src/display/new_renderer.c`
2. Create with `renderer_new_create()`
3. Use in `main.c`

### Adding a New Fingerprint Format

1. Extend `tls_info` structure with new format fields
2. Implement parsing in `tls.c`
3. Use `fingerprint_table` for tracking

## Compatibility Notes

- Requires DPDK 20.11 or later
- Tested with DPDK 22.11.1
- Supports vfio-pci and uio_pci_generic drivers
- Requires root privileges for hardware access

## Migration from Old Code

The old files remain in the project for reference:
- `src/main.c` (old) → `src/app/main.c` (new)
- `include/packet_parser.h` → `include/app/packet_parser.h`
- `include/flow_analyzer.h` → Split across `analyzer/` modules
- `include/stats_collector.h` → `include/app/stats_collector.h`
- `include/display.h` → `include/display/renderer.h`

New code uses DPDK structures and APIs for better performance.