#!/usr/bin/env python3
"""
测试流量生成脚本
用于生成HTTP、HTTPS、DNS、ICMP测试流量到指定接口
"""

import socket
import struct
import time
import argparse
import fcntl
import array
import random

# 协议常量
ETHER_TYPE_IPv4 = 0x0800
ETHER_TYPE_ARP  = 0x0806

IP_PROTOCOL_ICMP = 1
IP_PROTOCOL_TCP  = 6
IP_PROTOCOL_UDP  = 17

PORT_HTTP   = 80
PORT_HTTPS  = 443
PORT_DNS    = 53

# TLS常量
TLS_TYPE_HANDSHAKE = 22
TLS_HS_CLIENT_HELLO = 1
TLS_VERSION_1_2 = 0x0303

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
    data_offset_reserved_flags = (5 << 12) | flags
    window = 5840
    checksum = 0  # 简化
    urgent_ptr = 0

    tcp_header = struct.pack('!HHIIHHHH',
                            src_port, dst_port, seq, ack,
                            data_offset_reserved_flags, window, checksum, urgent_ptr)

    return tcp_header + payload

# 构造UDP数据包
def build_udp_packet(src_port, dst_port, payload):
    length = 8 + len(payload)
    checksum = 0  # 简化

    udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum)

    return udp_header + payload

# 构造ICMP Echo请求
def build_icmp_echo_request(seq=1):
    icmp_type = 8  # Echo Request
    icmp_code = 0
    checksum = 0
    identifier = 1

    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, seq)

    return icmp_header

# 构造HTTP请求
def build_http_request(path='/', method='GET'):
    http_request = f"{method} {path} HTTP/1.1\r\n"
    http_request += "Host: example.com\r\n"
    http_request += "User-Agent: DPDK-Traffic-Analyzer\r\n"
    http_request += "Accept: */*\r\n"
    http_request += "Connection: close\r\n"
    http_request += "\r\n"

    return http_request.encode()

# 构造TLS ClientHello
def build_tls_clienthello(version=TLS_VERSION_1_2):
    # TLS Record Layer Header
    content_type = TLS_TYPE_HANDSHAKE
    tls_record_version = version
    length = 0  # 将在后面填充

    # TLS Handshake Header
    msg_type = TLS_HS_CLIENT_HELLO
    handshake_length = 0  # 将在后面填充
    protocol_version = version

    # Random (32 bytes)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])

    # Session ID
    session_id_length = 0

    # Cipher Suites
    cipher_suites = struct.pack('!H', 2)  # Length: 2 bytes
    cipher_suites += struct.pack('!H', 0x002F)  # TLS_RSA_WITH_AES_128_CBC_SHA

    # Compression Methods
    compression_methods = struct.pack('!B', 1)  # Length: 1 byte
    compression_methods += struct.pack('!B', 0)  # NULL compression

    # Handshake message body
    handshake_body = struct.pack('!B', protocol_version >> 8)
    handshake_body += struct.pack('!B', protocol_version & 0xFF)
    handshake_body += random_bytes
    handshake_body += struct.pack('!B', session_id_length)
    handshake_body += cipher_suites
    handshake_body += compression_methods

    # Update handshake length (3 bytes)
    handshake_length = len(handshake_body)
    handshake_header = struct.pack('!B', msg_type)
    handshake_header += struct.pack('!I', handshake_length >> 8)[1:]  # 3 bytes

    # TLS handshake message
    tls_handshake = handshake_header + handshake_body

    # Update TLS record length
    length = len(tls_handshake)
    tls_record = struct.pack('!B', content_type)
    tls_record += struct.pack('!H', tls_record_version)
    tls_record += struct.pack('!H', length)

    return tls_record + tls_handshake

# 构造DNS查询
def build_dns_query(domain, qtype=1):  # qtype=1 for A record
    # DNS Header
    transaction_id = 0x1234
    flags = 0x0100  # Recursion desired
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    dns_header = struct.pack('!HHHHHH', transaction_id, flags, questions,
                            answer_rrs, authority_rrs, additional_rrs)

    # Encode domain name
    dns_question = b''
    labels = domain.split('.')
    for label in labels:
        dns_question += struct.pack('!B', len(label))
        dns_question += label.encode()
    dns_question += b'\x00'  # End of domain name

    # Query type and class
    dns_question += struct.pack('!H', qtype)  # Type: A (1), AAAA (28), etc.
    dns_question += struct.pack('!H', 1)      # Class: IN (1)

    return dns_header + dns_question

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

def generate_random_ip():
    """Generate a random IP address"""
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_random_mac():
    """Generate a random MAC address"""
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

def generate_random_domain():
    """Generate a random domain name"""
    prefixes = ['www', 'mail', 'ftp', 'api', 'cdn', 'static', 'img', 'video', 'test', 'demo']
    domains = ['example', 'test', 'mysite', 'cloud', 'service', 'app', 'data', 'content']
    tlds = ['.com', '.net', '.org', '.io', '.co', '.dev']

    prefix = random.choice(prefixes)
    domain_name = random.choice(domains) + str(random.randint(1, 100))
    tld = random.choice(tlds)

    return f'{prefix}.{domain_name}{tld}'

def generate_random_path():
    """Generate a random URL path"""
    paths = ['/api/v1/users', '/images/avatars', '/static/css', '/products/list',
             '/search', '/login', '/register', '/dashboard', '/settings/profile']
    if random.random() < 0.5:
        path = random.choice(paths)
        if random.random() < 0.3:
            path += f'?id={random.randint(1, 1000)}'
        return path
    else:
        return f'/page{random.randint(1, 999)}'

def generate_http_traffic(interface, packet_count=1000, delay=0.001):
    """生成HTTP测试流量 - 随机化参数"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

        src_mac = get_interface_mac(interface)
        src_ip = get_interface_ip(interface)

        if not src_mac:
            print(f"Warning: Cannot get MAC address for {interface}, using default")
            src_mac = generate_random_mac()

        dst_mac = generate_random_mac()
        dst_ip = generate_random_ip()

        print(f"Generating HTTP traffic on {interface}")
        print(f"Source MAC: {src_mac}, Source IP: {src_ip}")
        print(f"Destination MAC: {dst_mac}, Destination IP: {dst_ip}")
        print("Randomizing: IPs, ports, paths, timing")
        print("Press Ctrl+C to stop\n")

        for i in range(packet_count):
            # Random source port
            src_port = random.randint(1024, 65535)

            # Random HTTP method and path
            methods = ['GET', 'GET', 'GET', 'POST', 'HEAD', 'PUT', 'DELETE']
            method = random.choice(methods)
            path = generate_random_path()

            http_request = build_http_request(path=path, method=method)

            tcp_seq = random.randint(1, 4294967295)
            tcp_seg = build_tcp_segment(src_port, PORT_HTTP, tcp_seq, 0, 0x18, http_request)

            ip_packet = build_ip_packet(src_ip, dst_ip, IP_PROTOCOL_TCP, tcp_seg)

            eth_frame = build_ethernet_frame(src_mac, dst_mac, ETHER_TYPE_IPv4)

            full_frame = eth_frame + ip_packet
            sock.sendto(full_frame, (interface, 0))

            # Randomize timing
            current_delay = delay * random.uniform(0.5, 2.0)

            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1}/{packet_count} HTTP packets")

            time.sleep(current_delay)

        print(f"\nCompleted! Sent {packet_count} HTTP packets.")
        sock.close()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

def generate_https_traffic(interface, packet_count=1000, delay=0.001):
    """生成HTTPS/TLS测试流量 - 随机化参数"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

        src_mac = get_interface_mac(interface)
        src_ip = get_interface_ip(interface)

        if not src_mac:
            print(f"Warning: Cannot get MAC address for {interface}, using default")
            src_mac = generate_random_mac()

        dst_mac = generate_random_mac()
        dst_ip = generate_random_ip()

        print(f"Generating HTTPS/TLS traffic on {interface}")
        print(f"Source MAC: {src_mac}, Source IP: {src_ip}")
        print(f"Destination MAC: {dst_mac}, Destination IP: {dst_ip}")
        print("Randomizing: IPs, ports, TLS versions, timing")
        print("Press Ctrl+C to stop\n")

        # Randomize TLS versions
        tls_versions = [TLS_VERSION_1_2, TLS_VERSION_1_3]

        for i in range(packet_count):
            src_port = random.randint(1024, 65535)

            # Randomize TLS version
            tls_version = random.choice(tls_versions)

            tls_clienthello = build_tls_clienthello(version=tls_version)

            tcp_seq = random.randint(1, 4294967295)
            tcp_seg = build_tcp_segment(src_port, PORT_HTTPS, tcp_seq, 0, 0x18, tls_clienthello)

            ip_packet = build_ip_packet(src_ip, dst_ip, IP_PROTOCOL_TCP, tcp_seg)

            eth_frame = build_ethernet_frame(src_mac, dst_mac, ETHER_TYPE_IPv4)

            full_frame = eth_frame + ip_packet
            sock.sendto(full_frame, (interface, 0))

            # Randomize timing
            current_delay = delay * random.uniform(0.5, 2.0)

            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1}/{packet_count} HTTPS packets")

            time.sleep(current_delay)

        print(f"\nCompleted! Sent {packet_count} HTTPS packets.")
        sock.close()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

def generate_dns_traffic(interface, packet_count=1000, delay=0.001):
    """生成DNS测试流量 - 随机化参数"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

        src_mac = get_interface_mac(interface)
        src_ip = get_interface_ip(interface)

        if not src_mac:
            print(f"Warning: Cannot get MAC address for {interface}, using default")
            src_mac = generate_random_mac()

        dst_mac = generate_random_mac()
        dst_ip = generate_random_ip()

        print(f"Generating DNS traffic on {interface}")
        print(f"Source MAC: {src_mac}, Source IP: {src_ip}")
        print(f"Destination MAC: {dst_mac}, Destination IP: {dst_ip}")
        print("Randomizing: IPs, ports, domains, query types, timing")
        print("Press Ctrl+C to stop\n")

        # DNS query types
        query_types = [
            (1, 'A'),      # IPv4 address
            (28, 'AAAA'),  # IPv6 address
            (5, 'CNAME'),  # Canonical name
            (15, 'MX'),    # Mail exchange
            (16, 'TXT'),   # Text
            (2, 'NS'),     # Name server
            (12, 'PTR'),   # Pointer
        ]

        for i in range(packet_count):
            # Random source port
            src_port = random.randint(1024, 65535)

            # Random domain and query type
            domain = generate_random_domain()
            qtype_num, qtype_name = random.choice(query_types)

            dns_query = build_dns_query(domain, qtype=qtype_num)

            udp_packet = build_udp_packet(src_port, PORT_DNS, dns_query)

            ip_packet = build_ip_packet(src_ip, dst_ip, IP_PROTOCOL_UDP, udp_packet)

            eth_frame = build_ethernet_frame(src_mac, dst_mac, ETHER_TYPE_IPv4)

            full_frame = eth_frame + ip_packet
            sock.sendto(full_frame, (interface, 0))

            # Randomize timing
            current_delay = delay * random.uniform(0.5, 2.0)

            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1}/{packet_count} DNS packets")

            time.sleep(current_delay)

        print(f"\nCompleted! Sent {packet_count} DNS packets.")
        sock.close()

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

def generate_icmp_traffic(interface, packet_count=1000, delay=0.001):
    """生成ICMP测试流量 - 随机化参数"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

        src_mac = get_interface_mac(interface)
        src_ip = get_interface_ip(interface)

        if not src_mac:
            print(f"Warning: Cannot get MAC address for {interface}, using default")
            src_mac = generate_random_mac()

        dst_mac = generate_random_mac()
        dst_ip = generate_random_ip()

        print(f"Generating ICMP traffic on {interface}")
        print(f"Source MAC: {src_mac}, Source IP: {src_ip}")
        print(f"Destination MAC: {dst_mac}, Destination IP: {dst_ip}")
        print("Randomizing: IPs, sequence numbers, timing")
        print("Press Ctrl+C to stop\n")

        # ICMP types
        icmp_types = [
            (8, 0),   # Echo Request
            (8, 0),   # Echo Request (more common)
            (8, 0),   # Echo Request (more common)
            (0, 0),   # Echo Reply (simulate response)
            (3, 1),   # Destination Unreachable - Host Unreachable
        ]

        for i in range(packet_count):
            # Random ICMP type and code
            icmp_type, icmp_code = random.choice(icmp_types)
            seq_num = random.randint(1, 65535)
            identifier = random.randint(1, 65535)

            icmp_packet = build_icmp_echo_request(seq=seq_num)
            # Modify the ICMP header with our random values
            icmp_bytes = bytearray(icmp_packet)
            icmp_bytes[0] = icmp_type  # Type
            icmp_bytes[1] = icmp_code  # Code
            icmp_bytes[4] = identifier >> 8  # ID high byte
            icmp_bytes[5] = identifier & 0xFF  # ID low byte
            icmp_packet = bytes(icmp_bytes)

            ip_packet = build_ip_packet(src_ip, dst_ip, IP_PROTOCOL_ICMP, icmp_packet)

            eth_frame = build_ethernet_frame(src_mac, dst_mac, ETHER_TYPE_IPv4)

            full_frame = eth_frame + ip_packet
            sock.sendto(full_frame, (interface, 0))

            # Randomize timing
            current_delay = delay * random.uniform(0.5, 2.0)

            if (i + 1) % 100 == 0:
                print(f"Sent {i + 1}/{packet_count} ICMP packets")

            time.sleep(current_delay)

        print(f"\nCompleted! Sent {packet_count} ICMP packets.")
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
    parser.add_argument('-t', '--type', default='http',
                        choices=['http', 'https', 'dns', 'icmp', 'tcp'],
                        help='Traffic type: http, https, dns, icmp, or tcp (default: http)')

    args = parser.parse_args()

    print(f"Traffic type: {args.type.upper()}")

    if args.type == 'http':
        generate_http_traffic(args.interface, args.count, args.delay)
    elif args.type == 'https':
        generate_https_traffic(args.interface, args.count, args.delay)
    elif args.type == 'dns':
        generate_dns_traffic(args.interface, args.count, args.delay)
    elif args.type == 'icmp':
        generate_icmp_traffic(args.interface, args.count, args.delay)
    elif args.type == 'tcp':
        # Fallback to original TCP traffic
        generate_http_traffic(args.interface, args.count, args.delay)