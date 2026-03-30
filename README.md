# DPDK Traffic Analyzer

基于DPDK的高性能流量分析器，支持HTTP/HTTPS/DNS/ICMP协议解析、TLS指纹分析（JA4格式）和实时统计展示。

## 功能特性

### 核心功能
- **高性能数据包处理**：使用DPDK PMD驱动，支持零拷贝和批量处理
- **多核并行处理**：支持多队列、多核心并行采集和分析
- **五元组流分析**：源IP、目的IP、源端口、目的端口、协议
- **实时统计**：每秒刷新流量统计，支持带宽计算
- **Top排名展示**：Top 5 流、源IP、目的IP、JA4指纹
- **双模式支持**：DPDK模式（高性能）和非DPDK模式（raw socket，用于开发测试）

### 协议分析
- **HTTP/HTTPS流量统计**：端口80/443流量分析
- **TLS握手解析**：ClientHello、ServerHello、TLS版本统计
- **JA4指纹分析**：生成TLS客户端指纹并统计Top 5
- **DNS深度分析**：A/AAAA记录查询统计、响应统计
- **ICMP流量统计**：Echo请求/响应统计

### 显示特性
- **紧凑格式化输出**：无颜色、无边框、文字对齐
- **地理定位显示**：IP地址对应国家代码
- **应用层协议标注**：流中标注H(HTTP)、S(HTTPS)、D(DNS)等
- **带宽实时计算**：基于时间增量的动态带宽计算

## 构建与运行

### 快速开始

```bash
# 克隆项目
cd dpdkDemo

# 构建（非DPDK模式，无需DPDK依赖）
make nodpdk

# 运行（非DPDK模式）
sudo ./build/traffic_analyzer -i eth0
```

### DPDK模式构建

```bash
# 安装DPDK依赖
sudo apt-get install -y dpdk dpdk-dev

# 配置Hugepages
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 构建DPDK模式
make dpdk

# 绑定网卡到DPDK驱动
sudo dpdk-devbind.py -b vfio-pci 0000:00:01.0

# 运行DPDK模式
sudo ./build/traffic_analyzer -c 0x3 -n 4 -- --port 0000:00:01.0
```

### 构建选项

```bash
make              # 自动检测并构建
make info         # 显示构建信息
make dpdk         # 强制使用DPDK模式
make nodpdk       # 强制使用非DPDK模式
make clean        # 清理构建产物
make clean-all    # 清理所有构建目录
```

### 运行参数

#### 非DPDK模式（Raw Socket）
```
./build/traffic_analyzer -i <interface>

参数:
  -i INTERFACE     网络接口（默认: eth0）
  --help          显示帮助信息

示例:
  ./build/traffic_analyzer -i eth0
```

#### DPDK模式
```
./build/traffic_analyzer [EAL options] -- [APP options]

EAL选项:
  -c COREMASK      CPU核心掩码（十六进制）
  -n NUM           内存通道数
  --file-prefix    大页文件前缀

应用选项:
  --port NAME      DPDK端口名称（默认: 0000:00:01.0）
  --queues N       RX/TX队列数量（默认: 1）
  --ring-size N    RX/TX环形缓冲区大小（默认: 512）

示例:
  ./build/traffic_analyzer -c 0x3 -n 4 -- --port 0000:00:01.0
  ./build/traffic_analyzer -c 0xF -n 4 --file-prefix dpdk_demo -- --queues 2
```

## 模块化架构

```
dpdkDemo/
├── include/
│   ├── core/              # 核心抽象层
│   │   ├── config.h       # 全局配置常量
│   │   ├── hash_table.h   # 通用哈希表抽象
│   │   └── types.h        # 通用类型定义
│   ├── protocol/          # 协议解析模块
│   │   ├── ethernet.h     # 以太网（DPDK/非DPDK兼容）
│   │   ├── ip.h           # IPv4（DPDK/非DPDK兼容）
│   │   ├── tcp.h          # TCP（DPDK/非DPDK兼容）
│   │   ├── udp.h          # UDP（DPDK/非DPDK兼容）
│   │   ├── icmp.h         # ICMP协议
│   │   ├── dns.h          # DNS协议解析
│   │   └── tls.h          # TLS协议 + JA4指纹
│   ├── analyzer/          # 流量分析模块
│   │   ├── flow_table.h   # 流量表（五元组）
│   │   ├── ip_table.h     # IP表（源/目的IP泛型实现）
│   │   ├── fingerprint_table.h  # JA4指纹表
│   │   └── geolocation.h  # IP地理定位
│   ├── stats/             # 统计模块
│   │   ├── counters.h     # 通用计数器注册表
│   │   └── traffic_stats.h # 流量统计
│   ├── display/           # 显示模块
│   │   ├── formatter.h    # 格式化工具
│   │   └── renderer.h     # 抽象渲染器接口
│   ├── app/               # 应用层
│   │   ├── packet_parser.h    # 统一包解析接口
│   │   └── stats_collector.h  # 统计收集器
│   └── dpdk_adapter.h     # DPDK接口适配器
│
└── src/
    ├── core/              # 核心实现
    ├── protocol/          # 协议实现
    ├── analyzer/          # 分析器实现
    ├── stats/             # 统计实现
    ├── display/           # 显示实现
    ├── app/               # 应用实现
    └── dpdk_adapter.c     # DPDK适配器实现
```

## 架构特点

### 模块独立性
- 每个协议模块独立编译和测试
- 核心抽象层可被任何模块复用
- 分析器模块无协议耦合
- DPDK/非DPDK模式通过条件编译支持

### 可扩展性
- 添加新协议无需修改现有代码
- 插件式统计和显示组件
- 支持多种输出格式

### 可维护性
- 清晰的职责划分
- 统一的接口规范
- 便于定位和修复问题

### 性能优先
- 优先使用DPDK提供的接口
- 零拷贝和批量处理
- 多核并行优化

## 输出示例

```
DPDK Traffic Analyzer

Packets: 1234567  Bytes: 1.23 GB  Bandwidth: 1.23 Gbps

IPv4:98.5%  IPv6:1.5%  ICMP:2.1%  TCP:65.2%  UDP:34.8%

HTTP:45678(12.34 MB)  HTTPS:89012(56.78 MB)  DNS:12345(1.23 MB)

Top 5 Flows:
 1. 192.168.1.1:80->10.0.0.1:54321 45000 12.34 MB
 2. 192.168.1.2:443->10.0.0.2:54322 42000 45.67 MB
 3. 192.168.1.3:53->10.0.0.3:54323 8000 1.23 MB
 4. 192.168.1.4:22->10.0.0.4:54324 5000 2.45 MB
 5. 192.168.1.5:8080->10.0.0.5:54325 3000 1.89 MB

Top 5 Src IPs:
 1. 192.168.1.1 45000 12.34 MB
 2. 192.168.1.2 42000 45.67 MB
 3. 192.168.1.3 8000 1.23 MB
 4. 192.168.1.4 5000 2.45 MB
 5. 192.168.1.5 3000 1.89 MB

Top 5 Dst IPs:
 1. 10.0.0.1 45000 12.34 MB
 2. 10.0.0.2 42000 45.67 MB
 3. 10.0.0.3 8000 1.23 MB
 4. 10.0.0.4 5000 2.45 MB
 5. 10.0.0.5 3000 1.89 MB

Top 5 JA4:
 1. t13d130113020a_h2 42000
 2. t13d1302130312_h2 3000
 3. t13d1301130312 2000
 4. t13d1301c03010_h2 1000
 5. t13d1302c02c11_h2 500

[Ctrl+C to exit]
```

## 环境要求

### 硬件要求
- x86_64架构CPU
- 支持SR-IOV或DPDK的网卡（DPDK模式）
- 至少2GB RAM

### 软件要求
- Linux内核 4.14+
- gcc 7.0+
- make
- DPDK 20.11或更高版本（DPDK模式，可选）

## 测试流量生成

### 使用内置流量生成脚本

```bash
# 生成HTTP流量
sudo python3 generate_traffic.py -i eth0 -n 100 -t http

# 生成HTTPS（TLS握手）流量
sudo python3 generate_traffic.py -i eth0 -n 100 -t https

# 生成DNS流量
sudo python3 generate_traffic.py -i eth0 -n 100 -t dns

# 生成ICMP流量
sudo python3 generate_traffic.py -i eth0 -n 100 -t icmp

# 混合流量（随机）
sudo python3 generate_traffic.py -i eth0 -n 500
```

### 流量生成脚本参数

```bash
python3 generate_traffic.py -h

Options:
  -i, --interface  网络接口 (默认: eth0)
  -n, --count      发送包数量 (默认: 1000)
  -d, --delay      包间隔时间（秒）(默认: 随机)
  -t, --type       报文类型: http, https, dns, icmp, mixed (默认: mixed)
```

## 扩展开发

### 添加新协议

1. 在 `include/protocol/` 创建新协议头文件
2. 在 `src/protocol/` 实现解析逻辑
3. 在 `src/app/packet_parser.c` 添加检测逻辑
4. 在 `include/stats/traffic_stats.h` 添加统计字段

### 添加新指纹格式

1. 扩展 `include/protocol/tls.h` 中的 `tls_info` 结构
2. 在 `src/protocol/tls.c` 实现指纹生成逻辑
3. 使用 `fingerprint_table` 进行统计

### 添加新输出格式

1. 实现 `renderer` 接口
2. 在 `src/display/` 创建新的渲染器
3. 在 `main.c` 中使用新渲染器

## 故障排除

### 编译错误

```bash
# 检查编译器版本
gcc --version

# 清理后重新构建
make clean-all
make nodpdk
```

### 权限错误

```bash
# 需要 root权限访问网络接口
sudo ./build/traffic_analyzer -i eth0
```

### DPDK模式初始化失败

```bash
# 检查Hugepages
cat /proc/meminfo | grep Huge

# 重新配置Hugepages
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 检查网卡状态
sudo dpdk-devbind.py --status
```

## 性能优化

### 批量处理
- 每次处理32个数据包（BURST_SIZE）
- 减少上下文切换
- 提高CPU缓存利用率

### 零拷贝
- 直接访问网卡DMA内存
- 避免数据包复制
- 引用计数支持共享

### 多核并行
- 独立核心处理数据包
- 核心0负责显示和控制
- 避免锁竞争

### 内存优化
- 使用大页减少TLB未命中
- 内存池预分配
- 每核心缓存避免锁

## 参考资源

- [DPDK官方文档](https://doc.dpdk.org/)
- [JA4指纹规范](https://github.com/FoxIO-SSJA4/JA4)
- [DPDK入门指南](https://doc.dpdk.org/guides/linux_gsg/)

## 许可证

MIT License