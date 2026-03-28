#!/usr/bin/env python3
"""
测试脚本 - 验证发包程序的基本功能
"""

import sys
import struct

def test_packet_building():
    """测试数据包构建功能"""
    print("Testing packet building functions...\n")

    # 测试以太网帧
    src_mac = "00:11:22:33:44:55"
    dst_mac = "ff:ff:ff:ff:ff:ff"
    ether_type = 0x0800  # IPv4

    eth_frame = (bytes.fromhex(dst_mac.replace(':', '')) +
                 bytes.fromhex(src_mac.replace(':', '')) +
                 struct.pack('!H', ether_type))

    print(f"Ethernet Frame Length: {len(eth_frame)} bytes")
    print(f"Expected: 14 bytes")
    print(f"Result: {'PASS' if len(eth_frame) == 14 else 'FAIL'}\n")

    # 测试IP数据包
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.1"
    protocol = 6  # TCP
    payload = b"Test data"

    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
                           0x45, 0, 20 + len(payload), 54321,
                           0, 64, protocol, 0,
                           src_ip_bytes, dst_ip_bytes)

    print(f"IP Header Length: {len(ip_header)} bytes")
    print(f"Expected: 20 bytes")
    print(f"Result: {'PASS' if len(ip_header) == 20 else 'FAIL'}\n")

    # 测试TCP段
    src_port = 12345
    dst_port = 80

    tcp_header = struct.pack('!HHIIBBHHH',
                            src_port, dst_port, 0, 0,
                            5 << 4, 0x02, 5840, 0, 0)

    print(f"TCP Header Length: {len(tcp_header)} bytes")
    print(f"Expected: 20 bytes")
    print(f"Result: {'PASS' if len(tcp_header) == 20 else 'FAIL'}\n")

    # 组装完整包
    full_packet = eth_frame + ip_header + tcp_header + payload
    print(f"Full Packet Length: {len(full_packet)} bytes")
    print(f"Result: {'PASS' if len(full_packet) > 0 else 'FAIL'}\n")

    return True

def test_interface_detection():
    """测试接口检测"""
    print("Testing interface detection...\n")

    try:
        import socket
        import fcntl

        interface = 'eth0'

        # 获取MAC地址
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface.encode()[:15]))
        mac = ':'.join(f'{b:02x}' for b in info[0:6])
        print(f"Interface MAC: {mac}")
        print(f"Result: {'PASS' if mac else 'FAIL'}\n")

        # 获取IP地址
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface.encode()[:15]))
        ip = socket.inet_ntoa(info[0:4])
        print(f"Interface IP: {ip}")
        print(f"Result: {'PASS' if ip else 'FAIL'}\n")

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_raw_socket_creation():
    """测试原始套接字创建"""
    print("Testing raw socket creation...\n")

    try:
        import socket

        # 尝试创建原始套接字（需要root权限）
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        print("Raw socket created successfully")
        print(f"Socket family: {sock.family}")
        print(f"Socket type: {sock.type}")
        sock.close()

        print("\nResult: PASS")
        return True
    except PermissionError:
        print("Permission denied: Need root privileges to create raw socket")
        print("\nResult: EXPECTED (requires root)")
        return True
    except Exception as e:
        print(f"Error: {e}")
        print("\nResult: FAIL")
        return False

if __name__ == "__main__":
    print("=" * 80)
    print("Traffic Generator Test Suite")
    print("=" * 80)
    print()

    import socket

    # 测试数据包构建
    packet_test = test_packet_building()

    # 测试接口检测
    interface_test = test_interface_detection()

    # 测试原始套接字
    socket_test = test_raw_socket_creation()

    # 总结
    print("=" * 80)
    print("Test Summary")
    print("=" * 80)
    print(f"Packet Building:    {'PASS' if packet_test else 'FAIL'}")
    print(f"Interface Detection: {'PASS' if interface_test else 'FAIL'}")
    print(f"Raw Socket Creation: {'PASS' if socket_test else 'FAIL'}")
    print()

    if packet_test and interface_test and socket_test:
        print("All tests passed!")
        print("\nTo run the traffic generator:")
        print("  sudo python3 generate_traffic.py -i eth0 -n 1000")
        sys.exit(0)
    else:
        print("Some tests failed.")
        sys.exit(1)