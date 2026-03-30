# DPDK Traffic Analyzer - Makefile with DPDK/Non-DPDK support

# Configuration
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11 \
         -I./include \
         -I./include/core \
         -I./include/protocol \
         -I./include/analyzer \
         -I./include/stats \
         -I./include/display \
         -I./include/app
LDFLAGS = -lpthread -lm

# DPDK configuration
DPDK_PATH ?= ./dpdk/dpdk-stable-22.11.1/build
DPDK_CFLAGS = -I$(DPDK_PATH)/include
DPDK_LDFLAGS = -L$(DPDK_PATH)/lib -ldpdk -Wl,-rpath,$(DPDK_PATH)/lib

# Check if we can build with DPDK
ifeq ($(USE_DPDK),1)
    ifneq ($(wildcard $(DPDK_PATH)/include),)
        CFLAGS += $(DPDK_CFLAGS) -DUSE_DPDK
        LDFLAGS += $(DPDK_LDFLAGS)
        DPDK_SOURCES = src/dpdk_adapter.c
        $(info Using DPDK from $(DPDK_PATH))
    else
        $(warning DPDK build directory not found, falling back to non-DPDK mode)
        USE_DPDK = 0
    endif
else
    $(info Building in non-DPDK mode (raw socket))
    DPDK_SOURCES =
endif

# Directories
BUILD_DIR = build

# Source files
CORE_SOURCES = src/core/hash_table.c src/core/types.c
PROTOCOL_SOURCES = src/protocol/ethernet.c src/protocol/ip.c \
                  src/protocol/icmp.c src/protocol/dns.c \
                  src/protocol/tls.c
ANALYZER_SOURCES = src/analyzer/flow_table.c src/analyzer/ip_table.c \
                   src/analyzer/fingerprint_table.c src/analyzer/geolocation.c
STATS_SOURCES = src/stats/counters.c src/stats/traffic_stats.c
DISPLAY_SOURCES = src/display/formatter.c src/display/renderer.c
APP_SOURCES = src/app/packet_parser.c src/app/stats_collector.c \
              src/app/main.c

ALL_SOURCES = $(DPDK_SOURCES) $(CORE_SOURCES) $(PROTOCOL_SOURCES) $(ANALYZER_SOURCES) \
              $(STATS_SOURCES) $(DISPLAY_SOURCES) $(APP_SOURCES)

# Object files
ALL_OBJECTS = $(ALL_SOURCES:src/%.c=$(BUILD_DIR)/%.o)

# Output
TARGET = $(BUILD_DIR)/traffic_analyzer

# Default target
all: $(TARGET)

# Check if DPDK is available
check-dpdk:
	@echo "DPDK path: $(DPDK_PATH)"
	@test -d $(DPDK_PATH)/include && echo "DPDK headers found" || echo "DPDK headers NOT found"

# Create build directories
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/dpdk_adapter
	@mkdir -p $(BUILD_DIR)/core
	@mkdir -p $(BUILD_DIR)/protocol
	@mkdir -p $(BUILD_DIR)/analyzer
	@mkdir -p $(BUILD_DIR)/stats
	@mkdir -p $(BUILD_DIR)/display
	@mkdir -p $(BUILD_DIR)/app

# Build target
$(TARGET): $(BUILD_DIR) $(ALL_OBJECTS)
	@echo "Linking $(TARGET)..."
	@echo "  USE_DPDK=$(USE_DPDK)"
	$(CC) $(ALL_OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files
$(BUILD_DIR)/%.o: src/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	@rm -rf $(BUILD_DIR)

# Clean all (including old build dirs)
clean-all:
	@rm -rf $(BUILD_DIR) build.cmake

# Build with DPDK
dpdk:
	@$(MAKE) USE_DPDK=1

# Build without DPDK
nodpdk:
	@$(MAKE) USE_DPDK=0

# Show info
info:
	@echo "=== DPDK Traffic Analyzer Build Info ==="
	@echo "CC:          $(CC)"
	@echo "CFLAGS:      $(CFLAGS)"
	@echo "LDFLAGS:     $(LDFLAGS)"
	@echo "USE_DPDK:    $(USE_DPDK)"
	@echo "DPDK path:   $(DPDK_PATH)"
	@echo "Target:      $(TARGET)"
	@echo "======================================"

.PHONY: all clean clean-all check-dpdk dpdk nodpdk info