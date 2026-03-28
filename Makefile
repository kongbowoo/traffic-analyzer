# Makefile for DPDK Traffic Analyzer

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
LDFLAGS = -lpthread

# Source files
SRCS = src/main.c src/packet_parser.c src/flow_analyzer.c src/stats_collector.c src/display.c
# Object files mirroring source directory structure
OBJS = $(SRCS:.c=.o)
OBJS := $(addprefix build/,$(OBJS))

# Target executable
TARGET = build/traffic_analyzer

.PHONY: all clean run help

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Pattern rule to compile source files preserving directory structure
build/%.o: %.c | build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

# Create build directories mirroring source structure
build_dirs:
	@mkdir -p $(sort $(dir $(OBJS)))

build:
	@mkdir -p build

clean:
	rm -rf build

run: $(TARGET)
	./$(TARGET) -i eth0

help:
	@echo "DPDK Traffic Analyzer - Build and Run"
	@echo ""
	@echo "Targets:"
	@echo "  all    - Build the traffic analyzer"
	@echo "  clean  - Remove build artifacts"
	@echo "  run    - Build and run on eth0"
	@echo "  help   - Show this help message"
	@echo ""
	@echo "Usage after build:"
	@echo "  ./build/traffic_analyzer -i <interface> [-s <size>]"