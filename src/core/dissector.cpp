#include "dissector.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "util.h"

namespace nps {
namespace {

// ---------------------------------------------------------------------------
// 常量与格式化辅助
// ---------------------------------------------------------------------------

const char* ipProtoName(uint8_t proto) {
    switch (proto) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 89: return "OSPF";
        default: return nullptr;
    }
}

const char* icmpTypeName(uint16_t type, uint16_t code, bool v6) {
    if (!v6) {
        switch (type) {
            case 0: return "Echo (ping) reply";
            case 3:
                switch (code) {
                    case 0: return "Destination unreachable (net unreachable)";
                    case 1: return "Destination unreachable (host unreachable)";
                    case 3: return "Destination unreachable (port unreachable)";
                    default: return "Destination unreachable";
                }
            case 5: return "Redirect";
            case 8: return "Echo (ping) request";
            case 11:
                return (code == 0) ? "Time-to-live exceeded (in transit)"
                                   : "Time-to-live exceeded (reassembly)";
            case 13: return "Timestamp request";
            case 14: return "Timestamp reply";
            default: return "ICMP";
        }
    }
    switch (type) {
        case 1: return "Destination unreachable";
        case 2: return "Packet too big";
        case 3: return "Time exceeded";
        case 128: return "Echo (ping) request";
        case 129: return "Echo (ping) reply";
        case 133: return "Router solicitation";
        case 134: return "Router advertisement";
        case 135: return "Neighbor solicitation";
        case 136: return "Neighbor advertisement";
        case 137: return "Redirect";
        default: return "ICMPv6";
    }
}

const char* dnsTypeName(uint16_t t) {
    switch (t) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT";
        case 65: return "HTTPS";
        case 255: return "ANY";
        default: return "TYPE";
    }
}

std::string hex2(uint32_t v, int width = 2) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%0*x", width, v);
    return buf;
}

class Ctx {
public:
    Ctx(Packet& pkt, const uint8_t* data, size_t size) : p(pkt), d(data), len(size) {}

    Packet& p;
    const uint8_t* d;
    size_t len;

    bool ok(size_t off, size_t n) const { return off <= len && n <= len - off; }

    void fail(const std::string& why) {
        if (!p.malformed) {
            p.malformed = true;
            p.error = why;
        }
    }

    FieldNode& add(FieldNode& parent, const std::string& name, const std::string& value,
                   size_t off, size_t n) {
        parent.children.emplace_back(name, value, off, n);
        return parent.children.back();
    }

    // 只需要展示文本、不区分名称与取值的快捷形式
    FieldNode& add(FieldNode& parent, const std::string& text, size_t off, size_t n) {
        parent.children.emplace_back(text, "", off, n);
        return parent.children.back();
    }
};

// ---------------------------------------------------------------------------
// 前向声明
// ---------------------------------------------------------------------------

void parseIPv4(Ctx& c, size_t base);void parseIPv6(Ctx& c, size_t base);
void parseTcp(Ctx& c, size_t base);
void parseUdp(Ctx& c, size_t base);
void parseIcmp(Ctx& c, size_t base, bool v6);
void parseDns(Ctx& c, size_t base, bool tcp);
void parseHttp(Ctx& c, size_t base, size_t payloadLen);
void parseTls(Ctx& c, size_t base, size_t payloadLen);

bool looksLikeHttpImpl(const uint8_t* p, size_t len) {
    static const char* kMethods[] = {"GET ",     "POST ",   "HEAD ", "PUT ",   "DELETE ",
                                     "OPTIONS ", "PATCH ",  "TRACE ", "CONNECT "};
    for (const char* m : kMethods) {
        const size_t n = std::strlen(m);
        if (len >= n && std::memcmp(p, m, n) == 0) return true;
    }
    return len >= 5 && std::memcmp(p, "HTTP/", 5) == 0;
}

// ---------------------------------------------------------------------------
// 链路层
// ---------------------------------------------------------------------------

void parseEthernet(Ctx& c, size_t base) {
    Packet& p = c.p;
    if (!c.ok(base, 14)) {
        c.fail("Ethernet 头部长度不足");
        return;
    }
    FieldNode& eth = c.add(p.root, "Ethernet II", "", base, 14);

    const uint8_t* e = c.d + base;
    p.hasEth = true;
    p.ethDst = macToString(e);
    p.ethSrc = macToString(e + 6);
    p.ethType = readBe16(e + 12);
    c.add(eth, "Destination: " + p.ethDst, base, 6);
    c.add(eth, "Source: " + p.ethSrc, base + 6, 6);

    size_t l3off = base + 14;
    int vlanDepth = 0;
    // 802.1Q / QinQ：最多支持三层标签
    while ((p.ethType == 0x8100 || p.ethType == 0x88a8) && c.ok(l3off, 4) && vlanDepth < 3) {
        const uint16_t tci = readBe16(c.d + l3off);
        const uint16_t inner = readBe16(c.d + l3off + 2);
        p.hasVlan = true;
        p.vlanId = tci & 0x0fff;
        c.add(eth,
              "802.1Q VLAN, PRI: " + std::to_string((tci >> 13) & 0x7) +
                  ", DEI: " + std::to_string((tci >> 12) & 0x1) +
                  ", ID: " + std::to_string(p.vlanId),
              l3off, 4);
        p.ethType = inner;
        l3off += 4;
        ++vlanDepth;
    }
    c.add(eth, "Type: 0x" + hex2(p.ethType, 4) +
                   (p.ethType == 0x0800   ? " (IPv4)"
                    : p.ethType == 0x86dd ? " (IPv6)"
                    : p.ethType == 0x0806 ? " (ARP)"
                                          : ""),
          l3off - 2, 2);

    switch (p.ethType) {
        case 0x0800:
            p.l3 = L3Proto::IPv4;
            break;
        case 0x86dd:
            p.l3 = L3Proto::IPv6;
            break;
        case 0x0806:
            p.l3 = L3Proto::Arp;
            break;
        default:
            p.info = "Ethernet 类型 0x" + hex2(p.ethType, 4);
            return;
    }

    if (p.l3 == L3Proto::Arp) {
        FieldNode& arp = c.add(p.root, "Address Resolution Protocol", "", l3off, c.len - l3off);
        if (!c.ok(l3off, 8)) {
            c.fail("ARP 头部长度不足");
            return;
        }
        const uint8_t* a = c.d + l3off;
        const uint16_t htype = readBe16(a);
        const uint16_t ptype = readBe16(a + 2);
        const uint8_t hlen = a[4];
        const uint8_t plen = a[5];
        const uint16_t op = readBe16(a + 6);
        c.add(arp, "Hardware type: Ethernet (" + std::to_string(htype) + ")", l3off, 2);
        c.add(arp, "Protocol type: IPv4 (0x" + hex2(ptype, 4) + ")", l3off + 2, 2);
        c.add(arp, "Hardware size: " + std::to_string(hlen), l3off + 4, 1);
        c.add(arp, "Protocol size: " + std::to_string(plen), l3off + 5, 1);
        c.add(arp,
              "Opcode: " + std::string(op == 1 ? "request (1)" : op == 2 ? "reply (2)" : "?"),
              l3off + 6, 2);
        const size_t need = 8 + 2 * (static_cast<size_t>(hlen) + plen);
        if (c.ok(l3off, need) && hlen == 6 && plen == 4) {
            const std::string sha = macToString(a + 8);
            const std::string spa = ipv4ToString(a + 8 + hlen);
            const std::string tha = macToString(a + 8 + hlen + plen);
            const std::string tpa = ipv4ToString(a + 8 + hlen + plen + hlen);
            c.add(arp, "Sender MAC address: " + sha, l3off + 8, 6);
            c.add(arp, "Sender IP address: " + spa, l3off + 8 + hlen, plen);
            c.add(arp, "Target MAC address: " + tha, l3off + 8 + hlen + plen, 6);
            c.add(arp, "Target IP address: " + tpa, l3off + 8 + hlen + plen + hlen, plen);
            p.srcAddr = spa;
            p.dstAddr = tpa;
            p.hasL3 = true;
            p.appProto = "ARP";
            p.info = (op == 1) ? ("Who has " + tpa + "? Tell " + spa)
                               : (spa + " is at " + sha);
        } else {
            c.fail("ARP 地址字段长度异常");
        }
        return;
    }

    if (p.l3 == L3Proto::IPv4) {
        parseIPv4(c, l3off);
    } else {
        parseIPv6(c, l3off);
    }
}

// ---------------------------------------------------------------------------
// 网络层
// ---------------------------------------------------------------------------

void parseIPv4(Ctx& c, size_t base) {
    Packet& p = c.p;
    if (!c.ok(base, 20)) {
        c.fail("IPv4 头部长度不足");
        return;
    }
    const uint8_t* ip = c.d + base;
    const uint8_t version = ip[0] >> 4;
    const uint8_t ihl = (ip[0] & 0x0f) * 4;
    if (version != 4 || ihl < 20 || !c.ok(base, ihl)) {
        c.fail("IPv4 头部非法");
        return;
    }
    const uint16_t totalLen = readBe16(ip + 2);
    const uint16_t id = readBe16(ip + 4);
    const uint16_t flagsFrag = readBe16(ip + 6);
    p.ttl = ip[8];
    const uint8_t proto = ip[9];
    p.srcAddr = ipv4ToString(ip + 12);
    p.dstAddr = ipv4ToString(ip + 16);
    p.ipId = id;
    p.hasL3 = true;
    p.l3 = L3Proto::IPv4;

    const bool mf = (flagsFrag & 0x2000) != 0;
    const uint16_t fragOffset = static_cast<uint16_t>((flagsFrag & 0x1fff) * 8);
    p.fragmented = mf || fragOffset > 0;

    FieldNode& node = c.add(p.root,
                            "Internet Protocol Version 4, Src: " + p.srcAddr +
                                ", Dst: " + p.dstAddr,
                            "", base, ihl);
    c.add(node, "Version: 4", base, 1);
    c.add(node, "Header Length: " + std::to_string(ihl) + " bytes", base, 1);
    c.add(node, "Total Length: " + std::to_string(totalLen), base + 2, 2);
    c.add(node, "Identification: 0x" + hex2(id, 4) + " (" + std::to_string(id) + ")", base + 4, 2);
    c.add(node,
          "Flags: 0x" + hex2(flagsFrag >> 13, 1) + (mf ? " (More fragments)" : ""),
          base + 6, 1);
    c.add(node, "Fragment Offset: " + std::to_string(fragOffset / 8) + " (x8 bytes)", base + 6, 2);
    c.add(node, "Time to Live: " + std::to_string(p.ttl), base + 8, 1);
    const char* pn = ipProtoName(proto);
    c.add(node,
          "Protocol: " + std::string(pn ? pn : "Unknown") + " (" + std::to_string(proto) + ")",
          base + 9, 1);
    c.add(node, "Header Checksum: 0x" + hex2(readBe16(ip + 10), 4), base + 10, 2);
    c.add(node, "Source Address: " + p.srcAddr, base + 12, 4);
    c.add(node, "Destination Address: " + p.dstAddr, base + 16, 4);

    size_t l4off = base + ihl;
    size_t avail = c.len > l4off ? c.len - l4off : 0;
    if (totalLen >= ihl && totalLen - ihl < avail) {
        avail = totalLen - ihl;  // 去掉以太网尾部填充
    }

    // 非首片分片不解析传输层
    if (fragOffset > 0) {
        p.l4 = L4Proto::None;
        p.appProto = "IPv4 Fragment";
        p.info = "Fragmented IP protocol (offset " + std::to_string(fragOffset) + ")";
        return;
    }

    switch (proto) {
        case 6:
            p.l4 = L4Proto::Tcp;
            parseTcp(c, l4off);
            break;
        case 17:
            p.l4 = L4Proto::Udp;
            parseUdp(c, l4off);
            break;
        case 1:
            p.l4 = L4Proto::Icmp;
            parseIcmp(c, l4off, false);
            break;
        default: {
            const char* name = ipProtoName(proto);
            p.appProto = name ? name : ("IP/" + std::to_string(proto));
            p.info = "IPv4 " + p.appProto + " " + std::to_string(avail) + " bytes";
            break;
        }
    }
}

void parseIPv6(Ctx& c, size_t base) {
    Packet& p = c.p;
    if (!c.ok(base, 40)) {
        c.fail("IPv6 头部长度不足");
        return;
    }
    const uint8_t* ip = c.d + base;
    const uint32_t flow = readBe32(ip);
    const uint16_t payloadLen = readBe16(ip + 4);
    uint8_t next = ip[6];
    p.ttl = ip[7];
    p.srcAddr = ipv6ToString(ip + 8);
    p.dstAddr = ipv6ToString(ip + 24);
    p.hasL3 = true;
    p.l3 = L3Proto::IPv6;

    FieldNode& node = c.add(p.root,
                            "Internet Protocol Version 6, Src: " + p.srcAddr +
                                ", Dst: " + p.dstAddr,
                            "", base, 40);
    c.add(node, "Version: 6", base, 1);
    c.add(node, "Traffic Class: 0x" + hex2((flow >> 20) & 0xff, 2), base, 1);
    c.add(node, "Flow Label: 0x" + hex2(flow & 0xfffff, 5), base + 1, 3);
    c.add(node, "Payload Length: " + std::to_string(payloadLen), base + 4, 2);
    const char* nn = ipProtoName(next);
    c.add(node,
          "Next Header: " + std::string(nn ? nn : "Unknown") + " (" + std::to_string(next) + ")",
          base + 6, 1);
    c.add(node, "Hop Limit: " + std::to_string(p.ttl), base + 7, 1);
    c.add(node, "Source Address: " + p.srcAddr, base + 8, 16);
    c.add(node, "Destination Address: " + p.dstAddr, base + 24, 16);

    size_t off = base + 40;
    // 跳过常见扩展头
    int guard = 0;
    while (guard++ < 8) {
        if (next == 0 || next == 43 || next == 60) {  // Hop-by-Hop / Routing / Dest Opts
            if (!c.ok(off, 8)) {
                c.fail("IPv6 扩展头截断");
                return;
            }
            const uint8_t nh = c.d[off];
            const size_t extLen = (static_cast<size_t>(c.d[off + 1]) + 1) * 8;
            node.children.emplace_back("Extension Header: " + std::to_string(next),
                                       std::to_string(extLen) + " bytes", off, extLen);
            next = nh;
            off += extLen;
            continue;
        }
        if (next == 44) {  // Fragment
            if (!c.ok(off, 8)) {
                c.fail("IPv6 分片头截断");
                return;
            }
            const uint16_t fragField = readBe16(c.d + off + 2);
            p.fragmented = true;
            p.l4 = L4Proto::None;
            p.appProto = "IPv6 Fragment";
            p.info = std::string((fragField & 0xfff8) == 0 ? "First fragment" : "Fragment") +
                     " (offset " + std::to_string((fragField & 0xfff8)) + ")";
            node.children.emplace_back("Fragment Header", "", off, 8);
            return;
        }
        if (next == 51) {  // AH
            if (!c.ok(off, 8)) {
                c.fail("IPv6 AH 头截断");
                return;
            }
            const uint8_t nh = c.d[off];
            const size_t extLen = (static_cast<size_t>(c.d[off + 1]) + 2) * 4;
            next = nh;
            off += extLen;
            continue;
        }
        break;
    }

    switch (next) {
        case 6:
            p.l4 = L4Proto::Tcp;
            parseTcp(c, off);
            break;
        case 17:
            p.l4 = L4Proto::Udp;
            parseUdp(c, off);
            break;
        case 58:
            p.l4 = L4Proto::Icmpv6;
            parseIcmp(c, off, true);
            break;
        default: {
            const char* name = ipProtoName(next);
            p.appProto = name ? name : ("IPv6/" + std::to_string(next));
            p.info = "IPv6 " + p.appProto;
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 传输层
// ---------------------------------------------------------------------------

void parseTcp(Ctx& c, size_t base) {
    Packet& p = c.p;
    if (!c.ok(base, 20)) {
        c.fail("TCP 头部长度不足");
        return;
    }
    const uint8_t* t = c.d + base;
    p.srcPort = readBe16(t);
    p.dstPort = readBe16(t + 2);
    p.seq = readBe32(t + 4);
    p.ack = readBe32(t + 8);
    const size_t dataOff = static_cast<size_t>(t[12] >> 4) * 4;
    p.tcpFlags = t[13];
    p.window = readBe16(t + 14);
    if (dataOff < 20 || !c.ok(base, dataOff)) {
        c.fail("TCP 数据偏移非法");
        return;
    }
    const size_t segLen = c.len > base ? c.len - base : 0;
    p.payloadOffset = base + dataOff;
    p.payloadLength = static_cast<uint32_t>(segLen > dataOff ? segLen - dataOff : 0);

    FieldNode& node = c.add(p.root,
                            "Transmission Control Protocol, Src Port: " +
                                std::to_string(p.srcPort) +
                                ", Dst Port: " + std::to_string(p.dstPort) +
                                ", Seq: " + std::to_string(p.seq) +
                                ", Len: " + std::to_string(p.payloadLength),
                            "", base, dataOff);
    c.add(node, "Source Port: " + std::to_string(p.srcPort), base, 2);
    c.add(node, "Destination Port: " + std::to_string(p.dstPort), base + 2, 2);
    c.add(node, "Sequence Number: " + std::to_string(p.seq) + " (raw 0x" + hex2(p.seq, 8) + ")",
          base + 4, 4);
    c.add(node,
          std::string(p.tcpFlags & TcpFlags::Ack ? "Acknowledgment Number: " : "Acknowledgment Number (invalid): ") +
              std::to_string(p.ack),
          base + 8, 4);
    c.add(node, "Header Length: " + std::to_string(dataOff) + " bytes", base + 12, 1);
    c.add(node, "Flags: 0x" + hex2(p.tcpFlags, 3) + " (" + flagsToString(p.tcpFlags) + ")",
          base + 12, 2);
    c.add(node, "Window: " + std::to_string(p.window), base + 14, 2);
    c.add(node, "Checksum: 0x" + hex2(readBe16(t + 16), 4), base + 16, 2);
    c.add(node, "Urgent Pointer: " + std::to_string(readBe16(t + 18)), base + 18, 2);

    // 选项
    if (dataOff > 20) {
        FieldNode& opts = c.add(node, "Options", "", base + 20, dataOff - 20);
        size_t o = base + 20;
        const size_t end = base + dataOff;
        while (o < end) {
            const uint8_t kind = c.d[o];
            if (kind == 0) {
                c.add(opts, "End of Option List (EOL)", "", o, 1);
                break;
            }
            if (kind == 1) {
                c.add(opts, "No-Operation (NOP)", "", o, 1);
                o += 1;
                continue;
            }
            if (o + 1 >= end) break;
            const uint8_t olen = c.d[o + 1];
            if (olen < 2 || o + olen > end) break;
            if (kind == 2 && olen == 4) {
                c.add(opts, "Maximum Segment Size: " + std::to_string(readBe16(c.d + o + 2)), o, olen);
            } else if (kind == 3 && olen == 3) {
                c.add(opts, "Window Scale: " + std::to_string(c.d[o + 2]) +
                               " (multiply by " + std::to_string(1 << c.d[o + 2]) + ")", o, olen);
            } else if (kind == 4 && olen == 2) {
                c.add(opts, "SACK Permitted", o, olen);
            } else if (kind == 5 && olen >= 2) {
                c.add(opts,
                      "SACK: " + std::to_string((olen - 2) / 8) + " block(s)", o, olen);
            } else if (kind == 8 && olen == 10) {
                c.add(opts,
                      "Timestamps: TSval " + std::to_string(readBe32(c.d + o + 2)) +
                          ", TSecr " + std::to_string(readBe32(c.d + o + 6)),
                      o, olen);
            } else {
                c.add(opts, "Option kind " + std::to_string(kind) + " (" +
                                std::to_string(olen) + " bytes)",
                      o, olen);
            }
            o += olen;
        }
    }

    p.appProto = "TCP";

    std::ostringstream info;
    info << p.srcPort << " \u2192 " << p.dstPort << " [";
    const std::string fl = flagsToString(p.tcpFlags);
    info << (fl.empty() ? std::string("") : fl) << "]";
    info << " Seq=" << p.seq;
    if (p.tcpFlags & TcpFlags::Ack) info << " Ack=" << p.ack;
    info << " Win=" << p.window << " Len=" << p.payloadLength;
    p.info = info.str();
}

void parseUdp(Ctx& c, size_t base) {
    Packet& p = c.p;
    if (!c.ok(base, 8)) {
        c.fail("UDP 头部长度不足");
        return;
    }
    const uint8_t* u = c.d + base;
    p.srcPort = readBe16(u);
    p.dstPort = readBe16(u + 2);
    const uint16_t udpLen = readBe16(u + 4);
    size_t payloadLen = c.len > base + 8 ? c.len - base - 8 : 0;
    if (udpLen >= 8 && udpLen - 8 < payloadLen) payloadLen = udpLen - 8;
    p.payloadOffset = base + 8;
    p.payloadLength = static_cast<uint32_t>(payloadLen);

    FieldNode& node = c.add(p.root,
                            "User Datagram Protocol, Src Port: " + std::to_string(p.srcPort) +
                                ", Dst Port: " + std::to_string(p.dstPort),
                            "", base, 8);
    c.add(node, "Source Port: " + std::to_string(p.srcPort), base, 2);
    c.add(node, "Destination Port: " + std::to_string(p.dstPort), base + 2, 2);
    c.add(node, "Length: " + std::to_string(udpLen), base + 4, 2);
    c.add(node, "Checksum: 0x" + hex2(readBe16(u + 6), 4), base + 6, 2);

    p.appProto = "UDP";
    p.info = std::to_string(p.srcPort) + " \u2192 " + std::to_string(p.dstPort) +
             " Len=" + std::to_string(p.payloadLength);

    const bool dnsPort = (p.srcPort == 53 || p.dstPort == 53);
    if (dnsPort) {
        parseDns(c, p.payloadOffset, false);
    } else if (p.dstPort == 5353 || p.srcPort == 5353) {
        parseDns(c, p.payloadOffset, false);
    }
}

void parseIcmp(Ctx& c, size_t base, bool v6) {
    Packet& p = c.p;
    if (!c.ok(base, 4)) {
        c.fail("ICMP 头部长度不足");
        return;
    }
    const uint8_t* i = c.d + base;
    p.icmpType = i[0];
    p.icmpCode = i[1];
    FieldNode& node = c.add(p.root,
                            std::string(v6 ? "Internet Control Message Protocol v6" :
                                             "Internet Control Message Protocol"),
                            "", base, c.len - base);
    c.add(node, "Type: " + std::to_string(p.icmpType) + " (" +
                    icmpTypeName(p.icmpType, p.icmpCode, v6) + ")",
          base, 1);
    c.add(node, "Code: " + std::to_string(p.icmpCode), base + 1, 1);
    c.add(node, "Checksum: 0x" + hex2(readBe16(i + 2), 4), base + 2, 2);

    const bool echo = (!v6 && (p.icmpType == 0 || p.icmpType == 8)) ||
                      (v6 && (p.icmpType == 128 || p.icmpType == 129));
    if (echo && c.ok(base, 8)) {
        const uint16_t id = readBe16(i + 4);
        const uint16_t seq = readBe16(i + 6);
        c.add(node, "Identifier: 0x" + hex2(id, 4) + " (" + std::to_string(id) + ")", base + 4, 2);
        c.add(node, "Sequence Number: " + std::to_string(seq), base + 6, 2);
        if (c.len > base + 8) {
            c.add(node, "Data (" + std::to_string(c.len - base - 8) + " bytes)",
                  toPrintable(c.d + base + 8, std::min<size_t>(c.len - base - 8, 64)), base + 8,
                  c.len - base - 8);
        }
        p.info = std::string(icmpTypeName(p.icmpType, p.icmpCode, v6)) + " id=0x" + hex2(id, 4) +
                 " seq=" + std::to_string(seq);
    } else {
        p.info = icmpTypeName(p.icmpType, p.icmpCode, v6);
    }
    p.appProto = v6 ? "ICMPv6" : "ICMP";
}

// ---------------------------------------------------------------------------
// 应用层
// ---------------------------------------------------------------------------

void parseDns(Ctx& c, size_t base, bool tcp) {
    Packet& p = c.p;
    size_t off = base;
    if (tcp) {
        if (!c.ok(off, 2)) return;
        off += 2;  // TCP 上的 DNS 有 2 字节长度前缀
    }
    if (!c.ok(off, 12)) return;
    const uint8_t* d = c.d + off;
    const uint16_t id = readBe16(d);
    const uint16_t flags = readBe16(d + 2);
    const uint16_t qd = readBe16(d + 4);
    const uint16_t an = readBe16(d + 6);
    const bool response = (flags & 0x8000) != 0;

    FieldNode& node = c.add(p.root,
                            std::string("Domain Name System ") +
                                (response ? "(response)" : "(query)"),
                            "", off, c.len - off);
    c.add(node, "Transaction ID: 0x" + hex2(id, 4), off, 2);
    c.add(node,
          "Flags: 0x" + hex2(flags, 4) + (response ? " Response" : " Query") +
              ((flags & 0x0400) ? " Authoritative" : "") +
              ((flags & 0x0080) ? " Recursion desired" : ""),
          off + 2, 2);
    c.add(node, "Questions: " + std::to_string(qd), off + 4, 2);
    c.add(node, "Answer RRs: " + std::to_string(an), off + 6, 2);
    c.add(node, "Authority RRs: " + std::to_string(readBe16(d + 8)), off + 8, 2);
    c.add(node, "Additional RRs: " + std::to_string(readBe16(d + 10)), off + 10, 2);

    size_t cur = off + 12;
    std::string qname;
    uint16_t qtype = 0;
    for (uint16_t qi = 0; qi < qd && cur < c.len; ++qi) {
        std::string name;
        size_t ncur = cur;
        int guard = 0;
        while (ncur < c.len && guard++ < 128) {
            const uint8_t l = c.d[ncur];
            if (l == 0) {
                ++ncur;
                break;
            }
            if ((l & 0xc0) == 0xc0) {  // 压缩指针：问题段一般不出现，防御性处理
                ncur += 2;
                break;
            }
            if (ncur + 1 + l > c.len) break;
            if (!name.empty()) name += ".";
            name.append(reinterpret_cast<const char*>(c.d + ncur + 1), l);
            ncur += 1 + l;
        }
        if (ncur + 4 > c.len) break;
        const uint16_t t = readBe16(c.d + ncur);
        c.add(node, "Name: " + name, cur, ncur - cur);
        c.add(node, "Type: " + std::string(dnsTypeName(t)) + " (" + std::to_string(t) + ")", ncur, 2);
        c.add(node, "Class: IN (" + std::to_string(readBe16(c.d + ncur + 2)) + ")", ncur + 2, 2);
        if (qi == 0) {
            qname = name;
            qtype = t;
        }
        cur = ncur + 4;
    }

    // 简单提取第一条 A/AAAA 记录，便于列表展示
    std::string answerAddr;
    size_t acur = cur;
    for (uint16_t ai = 0; ai < an && acur + 12 <= c.len; ++ai) {
        // 跳过 name
        int guard = 0;
        while (acur < c.len && guard++ < 128) {
            const uint8_t l = c.d[acur];
            if (l == 0) {
                ++acur;
                break;
            }
            if ((l & 0xc0) == 0xc0) {
                acur += 2;
                break;
            }
            acur += 1 + l;
        }
        if (acur + 10 > c.len) break;
        const uint16_t at = readBe16(c.d + acur);
        const uint16_t rdlen = readBe16(c.d + acur + 8);
        const size_t rdata = acur + 10;
        if (rdata + rdlen > c.len) break;
        if (at == 1 && rdlen == 4) {
            answerAddr = ipv4ToString(c.d + rdata);
        } else if (at == 28 && rdlen == 16) {
            answerAddr = ipv6ToString(c.d + rdata);
        }
        acur = rdata + rdlen;
    }

    p.appProto = "DNS";
    p.info = std::string(response ? "Standard query response " : "Standard query ") +
             "0x" + hex2(id, 4) + " " + dnsTypeName(qtype) + " " + qname;
    if (!answerAddr.empty()) p.info += " \u2192 " + answerAddr;
}

void parseHttp(Ctx& c, size_t base, size_t payloadLen) {
    Packet& p = c.p;
    if (payloadLen == 0 || !c.ok(base, 1)) return;
    const std::string head = toPrintable(c.d + base, std::min<size_t>(payloadLen, 512));
    const size_t lineEnd = head.find("\\r\\n");
    const std::string firstLine = head.substr(0, lineEnd == std::string::npos ? head.size() : lineEnd);

    FieldNode& node = c.add(p.root, "Hypertext Transfer Protocol", "", base, payloadLen);
    c.add(node, "First line: " + firstLine, base, std::min<size_t>(payloadLen, firstLine.size()));

    std::string host;
    size_t pos = 0;
    while (pos < head.size()) {
        const size_t e = head.find("\\r\\n", pos);
        const std::string line = head.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
        if (containsNoCase(line, "Host:")) {
            host = line.substr(line.find(':') + 1);
            while (!host.empty() && host.front() == ' ') host.erase(host.begin());
        }
        if (e == std::string::npos) break;
        pos = e + 4;
    }
    if (!host.empty()) c.add(node, "Host: " + host, base, 0);

    p.appProto = "HTTP";
    if (!firstLine.empty() && firstLine.rfind("HTTP/", 0) == 0) {
        p.info = firstLine;
    } else {
        p.info = firstLine + (host.empty() ? "" : ("  Host: " + host));
    }
}

void parseTls(Ctx& c, size_t base, size_t payloadLen) {
    Packet& p = c.p;
    if (!c.ok(base, 5)) return;
    const uint8_t* t = c.d + base;
    const uint8_t contentType = t[0];
    const uint16_t version = readBe16(t + 1);
    const uint16_t recLen = readBe16(t + 3);
    (void)recLen;

    FieldNode& node = c.add(p.root, "Transport Layer Security", "", base, payloadLen);
    c.add(node, "Content Type: " + std::to_string(contentType) +
                    (contentType == 22 ? " (Handshake)" : contentType == 23 ? " (Application Data)" : ""),
          base, 1);
    c.add(node, "Version: 0x" + hex2(version, 4), base + 1, 2);
    c.add(node, "Record Length: " + std::to_string(recLen), base + 3, 2);

    std::string sni;
    if (contentType == 22 && c.ok(base + 5, 4) && t[5] == 1) {  // ClientHello
        size_t o = base + 9;  // 5 + 4
        if (c.ok(o, 34)) {
            o += 34;  // version(2) + random(32)
            if (c.ok(o, 1)) {
                const uint8_t sidLen = c.d[o];
                o += 1 + sidLen;
                if (c.ok(o, 2)) {
                    const uint16_t csLen = readBe16(c.d + o);
                    o += 2 + csLen;
                    if (c.ok(o, 1)) {
                        const uint8_t compLen = c.d[o];
                        o += 1 + compLen;
                        if (c.ok(o, 2)) {
                            const uint16_t extLen = readBe16(c.d + o);
                            o += 2;
                            const size_t extEnd = std::min<size_t>(o + extLen, c.len);
                            while (o + 4 <= extEnd) {
                                const uint16_t et = readBe16(c.d + o);
                                const uint16_t el = readBe16(c.d + o + 2);
                                if (o + 4 + el > extEnd) break;
                                if (et == 0 && el > 5) {  // server_name
                                    size_t so = o + 4 + 2;
                                    if (so + 3 <= o + 4 + el && c.d[so] == 0) {
                                        const uint16_t nl = readBe16(c.d + so + 1);
                                        if (so + 3 + nl <= c.len) {
                                            sni.assign(reinterpret_cast<const char*>(c.d + so + 3), nl);
                                        }
                                    }
                                }
                                o += 4 + el;
                            }
                        }
                    }
                }
            }
        }
        if (!sni.empty()) c.add(node, "Server Name Indication: " + sni, base, 0);
    }
    p.appProto = "TLS";
    const char* verLabel = "TLS";
    if (version == 0x0301) verLabel = "TLS 1.0";
    else if (version == 0x0302) verLabel = "TLS 1.1";
    else if (version == 0x0303) verLabel = "TLS 1.2/1.3";
    p.info = std::string(verLabel) +
             (contentType == 22 ? " Handshake" : contentType == 23 ? " Application Data" : "");
    if (!sni.empty()) p.info += " SNI=" + sni;
}

}  // namespace

// ---------------------------------------------------------------------------
// 对外入口
// ---------------------------------------------------------------------------

bool Dissector::looksLikeHttp(const uint8_t* p, size_t len) {
    return looksLikeHttpImpl(p, len);
}

void Dissector::dissect(Packet& p, int linkType) {
    p.root = FieldNode();
    p.root.name = "Frame " + std::to_string(p.index);
    p.root.value = std::to_string(p.caplen) + " bytes captured / " +
                   std::to_string(p.origlen) + " bytes on wire";
    p.root.offset = 0;
    p.root.length = p.caplen;

    if (p.raw.empty()) {
        p.malformed = true;
        p.error = "空报文";
        return;
    }

    Ctx c(p, p.raw.data(), p.raw.size());
    FieldNode& frame = c.add(p.root, "Frame", "", 0, 0);
    c.add(frame, "Frame Number: " + std::to_string(p.index), 0, 0);
    c.add(frame, "Captured Length: " + std::to_string(p.caplen) + " bytes", 0, 0);
    c.add(frame, "Frame Length: " + std::to_string(p.origlen) + " bytes", 0, 0);
    c.add(frame, "Arrival Time: " + std::to_string(p.ts), 0, 0);

    if (linkType == 0) {  // BSD loopback
        if (p.raw.size() < 4) {
            c.fail("Loopback 头部截断");
            return;
        }
        uint32_t fam = static_cast<uint32_t>(p.raw[0]) |
                       (static_cast<uint32_t>(p.raw[1]) << 8) |
                       (static_cast<uint32_t>(p.raw[2]) << 16) |
                       (static_cast<uint32_t>(p.raw[3]) << 24);
        FieldNode& nl = c.add(p.root, "Null/Loopback", "", 0, 4);
        c.add(nl, "Family: " + std::to_string(fam), 0, 4);
        if (fam == 2) {
            p.l3 = L3Proto::IPv4;
            parseIPv4(c, 4);
        } else if (fam == 30 || fam == 28 || fam == 24) {
            p.l3 = L3Proto::IPv6;
            parseIPv6(c, 4);
        }
        return;
    }
    if (linkType == 101 || linkType == 12) {  // RAW IP
        if ((p.raw[0] >> 4) == 6) {
            p.l3 = L3Proto::IPv6;
            parseIPv6(c, 0);
        } else {
            p.l3 = L3Proto::IPv4;
            parseIPv4(c, 0);
        }
        return;
    }
    if (linkType == 113) {  // Linux cooked capture
        if (p.raw.size() < 16) {
            c.fail("SLL 头部截断");
            return;
        }
        const uint16_t et = readBe16(p.raw.data() + 14);
        FieldNode& sll = c.add(p.root, "Linux cooked capture", "", 0, 16);
        c.add(sll, "Protocol: 0x" + hex2(et, 4), 14, 2);
        if (et == 0x0800) {
            p.l3 = L3Proto::IPv4;
            parseIPv4(c, 16);
        } else if (et == 0x86dd) {
            p.l3 = L3Proto::IPv6;
            parseIPv6(c, 16);
        }
        return;
    }
    parseEthernet(c, 0);

    if (p.malformed && p.info.empty()) {
        p.info = "Malformed: " + p.error;
    }

    // 应用层补充识别（仅对 TCP 载荷）
    if (p.l4 == L4Proto::Tcp && p.payloadLength > 0 && c.ok(p.payloadOffset, 1)) {
        const uint8_t* pl = p.raw.data() + p.payloadOffset;
        const size_t plLen = std::min<size_t>(p.payloadLength, p.raw.size() - p.payloadOffset);
        if (looksLikeHttpImpl(pl, plLen)) {
            parseHttp(c, p.payloadOffset, plLen);
        } else if (plLen >= 3 && pl[0] == 0x16 && pl[1] == 0x03) {
            parseTls(c, p.payloadOffset, plLen);
        } else if (p.payloadLength > 0) {
            p.appProto = "TCP";
        }
    }
}

}  // namespace nps
