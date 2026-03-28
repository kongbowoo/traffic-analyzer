# DPDK Traffic Analyzer

基于原始套接字的流量检测分析程序，支持在WSL2环境下运行。

## 功能特性

- 基础统计：流量大小、包数、带宽利用率
- 五元组分析：源IP、目的IP、源端口、目的端口、协议
- 实时显示：每秒刷新统计数据
- 协议分布：IPv4/IPv6、TCP/UDP统计
- Top流：显示流量最大的前5个流
- 无需外部依赖：使用Linux原始套接字，无需libpcap

## 环境要求

### WSL2/Linux 环境
- Ubuntu 20.04 或更高版本
- gcc, make
- Python 3.x (用于生成测试流量)

## 安装步骤

### 1. 编译程序

```bash
cd /home/wubo/dpdkDemo
make
```

### 2. 验证构建

```bash
ls -lh build/traffic_analyzer
```

## 使用方法

### 基本使用

```bash
sudo ./build/traffic_analyzer -i eth0
```

### 高级选项

```bash
./build/traffic_analyzer [OPTIONS]

Options:
  -i <interface>  网络接口名称 (默认: eth0)
  -s <size>       流表大小 (默认: 1024)
  -h              显示帮助信息
```

### 示例

```bash
# 捕获 eth0 接口的所有流量
sudo ./build/traffic_analyzer -i eth0

# 增大流表容量
sudo ./build/traffic_analyzer -i eth0 -s 4096

# 查看可用接口
ip link show
```

## 生成测试流量

### 使用内置流量生成脚本

```bash
# 发送1000个测试数据包
sudo python3 generate_traffic.py -i eth0 -n 1000

# 自定义参数
sudo python3 generate_traffic.py -i eth0 -n 5000 -d 0.0001
```

### 流量生成脚本参数

```bash
python3 generate_traffic.py -h
```

```
Options:
  -i, --interface  网络接口 (默认: eth0)
  -n, --count      发送包数量 (默认: 1000)
  -d, --delay      包间隔时间（秒）(默认: 0.001)
```

## 测试

### 运行测试套件

```bash
python3 test_generator.py
```

测试包括：
- 数据包构建功能
- 接口信息获取
- 原始套接字创建

## 输出示例

```
================================================================================
DPDK Traffic Analyzer - WSL2
================================================================================
Interface: eth0  |  RX Queue: 1  |  Core: 0
================================================================================
Total Statistics:
  Packets:  1,234,567       |  Bytes:  1.23 GB
  Bandwidth:  1.23 Gbps

Protocol Distribution:
  IPv4:   98.5%  |  IPv6:    1.5%
  TCP:    65.2%  |  UDP:    34.8%

Top 5 Flows:
  1. 192.168.1.1:80   ->  10.0.0.1:54321  (TCP)  |  123,456 pkts  |  12.34 MB
  2. 192.168.1.2:53   ->  10.0.0.2:54322  (UDP)  |  98,765 pkts   |  9.87 MB
  3. 192.168.1.3:443  ->  10.0.0.3:54323  (TCP)  |  87,654 pkts   |  8.76 MB
  4. 192.168.1.4:22   ->  10.0.0.4:54324  (TCP)  |  54,321 pkts   |  5.43 MB
  5. 192.168.1.5:8080 ->  10.0.0.5:54325  (TCP)  |  32,109 pkts   |  3.21 MB
================================================================================
[Press Ctrl+C to exit]
================================================================================
```

## 项目结构

```
dpdkDemo/
├── src/                      # 源代码
│   ├── main.c               # 主程序
│   ├── packet_parser.c      # 报文解析
│   ├── flow_analyzer.c      # 流量分析
│   ├── stats_collector.c    # 统计收集
│   ├── display.c            # 终端显示
│   └── dpdk_init.c          # DPDK初始化（参考代码）
├── include/                  # 头文件
│   ├── packet_parser.h
│   ├── flow_analyzer.h
│   ├── stats_collector.h
│   ├── display.h
│   └── dpdk_init.h
├── build/                    # 编译输出
│   ├── src/                 # 目标文件
│   │   ├── main.o
│   │   ├── packet_parser.o
│   │   ├── flow_analyzer.o
│   │   ├── stats_collector.o
│   │   └── display.o
│   └── traffic_analyzer    # 可执行文件
├── Makefile                  # 编译脚本
├── generate_traffic.py      # 流量生成脚本
├── test_generator.py        # 测试脚本
├── build.sh                 # 一键构建脚本
├── .gitignore               # Git忽略文件
└── README.md                # 本文件
```

## 构建命令

```bash
make          # 构建项目
make clean    # 清理构建产物
make run      # 构建并运行
make help     # 显示帮助信息
```

## 技术实现

### 网络捕获
- 使用Linux原始套接字（AF_PACKET, SOCK_RAW）
- 无需libpcap依赖
- 支持所有Linux网络接口

### 报文解析
- 以太网帧解析
- IPv4/IPv6头部解析
- TCP/UDP头部解析
- 五元组提取

### 流量分析
- 哈希表实现快速流查找
- 滑动窗口带宽计算
- 周期性统计快照

### 终端显示
- ANSI转义码实时刷新
- 格式化数据展示
- Top流排序显示

## DPDK 支持

本程序提供了DPDK初始化代码作为参考（`src/dpdk_init.c`）。

如需使用原生DPDK，需要：
1. 编译DPDK
2. 配置Hugepages
3. 绑定网卡到DPDK驱动
4. 修改代码使用DPDK API

## 故障排除

### 权限错误

原始套接字需要root权限：

```bash
sudo ./build/traffic_analyzer -i eth0
```

### 接口不存在

查看可用网络接口：

```bash
ip link show
```

### WSL2 网络问题

确保WSL2有网络访问权限，可以尝试：

```bash
# 在Windows PowerShell中重启WSL2
wsl --shutdown
```

### 编译错误

确保安装了必要的构建工具：

```bash
sudo apt-get install -y build-essential
```

## 许可证

MIT License