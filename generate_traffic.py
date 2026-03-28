#!/usr/bin/env python3
"""
测试流量生成脚本
用于生成简单的测试流量到指定接口
"""

import socket
import struct
import time
import argparse
import fcntl
import array

# 构造以太网帧
def build_ethernet_frame(src_mac, dst_mac, ether_type):
    return (bytes.fromhex(dst_mac.replace(':', '')) +
            bytes.fromhex(src_mac.replace(':', '')) +
            struct.pack('!H', ether_type))

# 构造IP数据包
def build_ip_packet(src_ip, dst_ip, protocol, payload):
    version_ihl = 0x45  # IPv4, 5 words
    tos = 0
    total_length = 20 + len(payload)
    id = 54321
    fragment_offset = 0
    ttl = 64
    checksum = 0  # 简化，实际需要计算

    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
                           version_ihl, tos, total_length, id,
                           fragment_offset, ttl, protocol, checksum,
                           src_ip_bytes, dst_ip_bytes)

    return ip_header + payload

# 构造TCP段
def build_tcp_segment(src_port, dst_port, seq, ack, flags, payload):
    # TCP header: data_offset(4 bits) + reserved(4 bits) + flags(8 bits)
    # data_offset = 5 (20 bytes header, no options)
    # reserved = 0
    data_offset_reserved_flags = (5 << 12) | flags
    window = 5840
    checksum = 0  # 简化
    urgent_ptr = 0

    tcp_header = struct.pack('!HHIIHHHH',
                            src_port, dst_port, seq, ack,
                            data_offset_reserved_flags, window, checksum, urgent_ptr)

    return tcp_header + payload

# 获取接口MAC地址
def get_interface_mac(interface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface.encode()[:15]))
        return ':'.join(f'{b:02x}' for b in info[0:6])
    except Exception as e:
        return None

# 获取接口IP地址
def get_interface_ip(interface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface.encode()[:15]))
        return socket.inet_ntoa(info[0:4])
    except Exception as e:
        return "192.168.1.100"  # 使用默认值

# 获取所有网络接口
def get_interfaces():
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        interfaces = []
        for line in lines[2:]:  # Skip header lines
            if ':' in line:
                interface = line.split(':')[0].strip()
                if interface and interface != 'lo':
                    interfaces.append(interface)
        return interfaces
    except Exception as e:
        return []

def generate_test_traffic(interface, packet_count=1000, delay=0.001):
    """生成测试流量"""
    try:
        # 创建原始套接字 (需要 root 权限)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

        # 源MAC地址 (使用接口的实际MAC)
        src_mac = get_interface_mac(interface)
        # 源IP地址
        src_ip = get_interface_ip(interface)

        # 如果无法获取MAC，使用默认值
        if not src_mac:
            print(f"Warning: Cannot get MAC address for {interface}, using default")
            src_mac = "00:11:22:33:44:55"

        # 目标地址 (使用广播地址)
        dst_mac = "ff:ff:ff:ff:ff:ff"
        dst_ip = "192.168.1.100"

        print(f"Generating {packet_count} packets on {interface}")
        print(f"Source MAC: {src_mac}, Source IP: {src_ip}")
        print(f"Destination MAC: {dst_mac}, Destination IP: {dst_ip}")
        print("Press Ctrl+C to stop\n")

        for i in range(packet_count):
            # 构造应用层载荷
            payload = b'Test packet data ' + str(i).encode()

            # 构造TCP段
            tcp_seq = i * len(payload)
            tcp_seg = build_tcp_segment(12345, 80, tcp_seq, 0, 0x02, payload)  # SYN flag

            # 构造IP数据包
            ip_packet = build_ip_packet(src_ip, dst_ip, 6, tcp_seg)  # Protocol 6 = TCP

            # 构造以太网帧
            eth_frame = build_ethernet_frame(src_mac, dst_mac, 0x0800)  # IPv4

            # 发送完整帧
            full_frame = eth_frame + ip_packet
            sock.sendto(full_frame, (interface, 0))

            # 显示进度
            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1}/{packet_count} packets")

            time.sleep(delay)

        print(f"\nCompleted! Sent {packet_count} packets.")
        sock.close()

    except PermissionError:
        print("Error: This script requires root privileges.")
        print("Please run with: sudo python3 generate_traffic.py")
    except FileNotFoundError:
        print(f"Error: Interface {interface} not found.")
        print("Available interfaces:")
        for iface in get_interfaces():
            print(f"  - {iface}")
    except KeyboardInterrupt:
        print("\nStopped by user.")
        sock.close()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate test network traffic')
    parser.add_argument('-i', '--interface', default='eth0',
                        help='Network interface to send traffic (default: eth0)')
    parser.add_argument('-n', '--count', type=int, default=1000,
                        help='Number of packets to send (default: 1000)')
    parser.add_argument('-d', '--delay', type=float, default=0.001,
                        help='Delay between packets in seconds (default: 0.001)')

    args = parser.parse_args()

    generate_test_traffic(args.interface, args.count, args.delay)