#!/usr/bin/env python3
"""生成用于功能验证的 pcap 文件（无需 root、无需第三方库）。

覆盖场景：
  http_basic.pcap   完整 TCP 三次握手 + HTTP GET/200 响应 + 四次挥手
  tcp_reorder.pcap  HTTP 报文被拆成多段，包含乱序与重传
  mixed.pcap        DNS、ICMP、IPv6+HTTP、802.1Q VLAN、TLS ClientHello(SNI)、畸形帧
  perf_200k.pcap    20 万条报文，用于吞吐/丢包测试
"""

import os
import struct
import sys

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64, ident=1):
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0,
        bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    csum = checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b"", window=65535):
    offset_flags = (5 << 12) | flags
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, window, 0, 0)
    pseudo = (bytes(map(int, src_ip.split("."))) + bytes(map(int, dst_ip.split(".")))
              + struct.pack("!BBH", 0, 6, len(header) + len(payload)))
    csum = checksum(pseudo + header + payload)
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, window, csum, 0)
    return header + payload


def udp(src_ip, dst_ip, sport, dport, payload):
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = (bytes(map(int, src_ip.split("."))) + bytes(map(int, dst_ip.split(".")))
              + struct.pack("!BBH", 0, 17, length))
    csum = checksum(pseudo + header + payload) or 0xFFFF
    header = struct.pack("!HHHH", sport, dport, length, csum)
    return header + payload


def icmp(payload_type, code, ident, seq, data=b"abcdefghijklmnop"):
    body = struct.pack("!BBHHH", payload_type, code, 0, ident, seq) + data
    csum = checksum(body)
    return body[:2] + struct.pack("!H", csum) + body[4:]


def ethernet(payload, ethertype=0x0800, vlan=None):
    if vlan is not None:
        header = MAC_B + MAC_A + struct.pack("!HHH", 0x8100, vlan & 0x0FFF, ethertype)
    else:
        header = MAC_B + MAC_A + struct.pack("!H", ethertype)
    return header + payload


def ipv6(src, dst, next_header, payload):
    import ipaddress
    header = (struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64)
              + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed)
    return header + payload


def tcp6(src, dst, sport, dport, seq, ack, flags, payload=b""):
    import ipaddress
    offset_flags = (5 << 12) | flags
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, 0, 0)
    pseudo = (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
              + struct.pack("!I3xB", len(header) + len(payload), 6))
    csum = checksum(pseudo + header + payload)
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 65535, csum, 0)
    return header + payload


def dns_query(txid, name, qtype=1):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def dns_response(txid, name, ip):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    question = labels + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(map(int, ip.split(".")))
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def tls_client_hello(sni="example.com"):
    name = sni.encode()
    sni_ext = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    ext = struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00"
            + struct.pack("!H", len(ext)) + ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        self.ts = 1763000000.0

    def add(self, frame, delta=0.001):
        self.ts += delta
        sec = int(self.ts)
        usec = int(round((self.ts - sec) * 1e6))
        self.f.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


def build_http_basic(path):
    w = PcapWriter(path)
    c, s = "192.168.1.100", "93.184.216.34"
    cp, sp = 49152, 80
    isn_c, isn_s = 1000, 5000
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c, 0, 0x02))))
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, isn_s, isn_c + 1, 0x12))))
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1, isn_s + 1, 0x10))))
    req = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
           b"User-Agent: NPS-Sniffer-Lab/1.0\r\nAccept: */*\r\n\r\n")
    body = b"<html><body><h1>Hello, NPS!</h1></body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1, isn_s + 1, 0x18, req))))
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, isn_s + 1, isn_c + 1 + len(req), 0x18, resp))))
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1 + len(req), isn_s + 1 + len(resp), 0x11))))
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, isn_s + 1 + len(resp), isn_c + 2 + len(req), 0x11))))
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 2 + len(req), isn_s + 2 + len(resp), 0x10))))
    w.close()
    return len(req), len(resp)


def build_tcp_reorder(path):
    """HTTP 请求被拆成三段，第二段先到、第三段后到，另有第二段的一次重传。"""
    w = PcapWriter(path)
    c, s = "10.0.0.5", "10.0.0.9"
    cp, sp = 52000, 8080
    isn_c = 7000
    body = b'{"user":"admin","pass":"123456"}'
    req = (b"POST /api/login HTTP/1.1\r\nHost: lab.local\r\nContent-Type: application/json\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    seg1, seg2, seg3 = req[:40], req[40:100], req[100:]
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c, 0, 0x02))))
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, 9000, isn_c + 1, 0x12))))
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1, 9001, 0x10))))
    # 乱序：seg2 / seg3 先于 seg1
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1 + 40, 9001, 0x18, seg2))))
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, 9001, isn_c + 1, 0x10))))
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, 9001, isn_c + 1, 0x10))))
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1 + 100, 9001, 0x18, seg3))))
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1, 9001, 0x18, seg1))))
    # 重传 seg2
    w.add(ethernet(ipv4(c, s, 6, tcp(c, s, cp, sp, isn_c + 1 + 40, 9001, 0x18, seg2))))
    resp = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
    w.add(ethernet(ipv4(s, c, 6, tcp(s, c, sp, cp, 9001, isn_c + 1 + len(req), 0x18, resp))))
    w.close()
    return req, resp


def build_mixed(path):
    w = PcapWriter(path)
    # DNS query / response
    q = udp("192.168.1.100", "8.8.8.8", 5353, 53, dns_query(0x1234, "example.com"))
    w.add(ethernet(ipv4("192.168.1.100", "8.8.8.8", 17, q)))
    a = udp("8.8.8.8", "192.168.1.100", 53, 5353, dns_response(0x1234, "example.com", "93.184.216.34"))
    w.add(ethernet(ipv4("8.8.8.8", "192.168.1.100", 17, a)))
    # ICMP echo request / reply
    w.add(ethernet(ipv4("192.168.1.100", "192.168.1.1", 1, icmp(8, 0, 0x0001, 1))))
    w.add(ethernet(ipv4("192.168.1.1", "192.168.1.100", 1, icmp(0, 0, 0x0001, 1))))
    # VLAN 100 上的 HTTP over IPv6
    req = b"GET /v6 HTTP/1.1\r\nHost: v6.lab\r\n\r\n"
    p6 = tcp6("fd00::1", "fd00::2", 40000, 80, 1, 1, 0x18, req)
    w.add(ethernet(ipv6("fd00::1", "fd00::2", 6, p6), 0x86DD, vlan=100))
    # TLS ClientHello with SNI
    hello = tls_client_hello("secure.example.org")
    w.add(ethernet(ipv4("192.168.1.100", "151.101.1.1", 6,
                        tcp("192.168.1.100", "151.101.1.1", 49700, 443, 1, 1, 0x18, hello))))
    # ARP request
    arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_A + bytes([192, 168, 1, 100])
           + b"\x00" * 6 + bytes([192, 168, 1, 1]))
    w.add(ethernet(arp, 0x0806))
    # 畸形帧：以太网类型声明 IPv4，但 IP 头被截断
    w.add(ethernet(b"\x45\x00", 0x0800))
    w.close()


def build_perf(path, count=200000):
    w = PcapWriter(path)
    c, s = "10.1.0.1", "10.1.0.2"
    payload = b"X" * 64
    for i in range(count):
        sport = 1024 + (i % 60000)
        frame = ethernet(ipv4(c, s, 6, tcp(c, s, sport, 80, i, i, 0x18, payload)))
        w.add(frame, delta=0.00005)
    w.close()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    build_http_basic(os.path.join(out, "http_basic.pcap"))
    build_tcp_reorder(os.path.join(out, "tcp_reorder.pcap"))
    build_mixed(os.path.join(out, "mixed.pcap"))
    if "--perf" in sys.argv:
        build_perf(os.path.join(out, "perf_200k.pcap"))
    print("生成完成:", out)
