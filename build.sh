#!/bin/bash
# 测试脚本 - 编译和运行流量分析器

set -e

echo "================================================================================"
echo "DPDK Traffic Analyzer - Build and Test"
echo "================================================================================"
echo ""

# 检查依赖
echo "Checking dependencies..."

if ! command -v gcc &> /dev/null; then
    echo "Error: gcc not found"
    exit 1
fi

if ! command -v make &> /dev/null; then
    echo "Error: make not found"
    exit 1
fi

if [ ! -f "/usr/include/pcap.h" ]; then
    echo "Warning: pcap.h not found"
    echo "Please install libpcap-dev:"
    echo "  sudo apt-get install -y libpcap-dev"
    exit 1
fi

echo "All dependencies found."
echo ""

# 编译
echo "Building..."
make clean
make

if [ $? -eq 0 ]; then
    echo "Build successful!"
else
    echo "Build failed!"
    exit 1
fi

echo ""
echo "================================================================================"
echo "Build completed successfully!"
echo "================================================================================"
echo ""
echo "To run the analyzer:"
echo "  sudo ./build/traffic_analyzer -i eth0"
echo ""
echo "To generate test traffic in another terminal:"
echo "  sudo python3 generate_traffic.py -i eth0 -n 1000"
echo ""