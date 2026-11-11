// 基础数据结构：解析结果、字段树、流记录
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nps {

// 协议字段树节点，offset/len 指向原始报文，用于详情面板与十六进制联动
struct FieldNode {
    std::string name;
    std::string value;
    size_t offset = 0;
    size_t length = 0;
    std::vector<FieldNode> children;

    FieldNode() = default;
    FieldNode(std::string n, std::string v, size_t off = 0, size_t len = 0)
        : name(std::move(n)), value(std::move(v)), offset(off), length(len) {}
};

enum class L3Proto : uint8_t { None = 0, Arp = 1, IPv4 = 2, IPv6 = 3 };
enum class L4Proto : uint8_t { None = 0, Icmp = 1, Tcp = 6, Udp = 17, Icmpv6 = 58 };

struct TcpFlags {
    static constexpr uint8_t Fin = 0x01;
    static constexpr uint8_t Syn = 0x02;
    static constexpr uint8_t Rst = 0x04;
    static constexpr uint8_t Psh = 0x08;
    static constexpr uint8_t Ack = 0x10;
    static constexpr uint8_t Urg = 0x20;
    static constexpr uint8_t Ece = 0x40;
    static constexpr uint8_t Cwr = 0x80;
};

// 单条报文的完整解析结果
struct Packet {
    int64_t index = 0;          // 序号，从 1 开始
    double ts = 0.0;            // 时间戳（秒）
    uint32_t caplen = 0;
    uint32_t origlen = 0;
    std::vector<uint8_t> raw;   // 抓到的原始字节

    // 链路层
    bool hasEth = false;
    std::string ethSrc;
    std::string ethDst;
    uint16_t ethType = 0;
    uint16_t vlanId = 0;
    bool hasVlan = false;

    // 网络层
    L3Proto l3 = L3Proto::None;
    std::string srcAddr;        // IP 或 ARP 地址
    std::string dstAddr;
    uint8_t ttl = 0;
    uint16_t ipId = 0;
    bool fragmented = false;
    bool hasL3 = false;

    // 传输层
    L4Proto l4 = L4Proto::None;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint16_t window = 0;
    uint8_t tcpFlags = 0;
    size_t payloadOffset = 0;
    uint32_t payloadLength = 0;
    uint16_t icmpType = 0;
    uint16_t icmpCode = 0;

    // 应用层
    std::string appProto;       // HTTP / DNS / TLS / ARP / ICMP ...
    std::string info;           // 列表摘要列

    // 进程归因
    int32_t pid = -1;
    std::string procName;

    // TCP 流编号（-1 表示不属于任何被跟踪的流）
    int64_t streamId = -1;
    // 该报文是否被判定为重传/乱序
    bool retransmission = false;
    bool outOfOrder = false;

    bool malformed = false;
    std::string error;

    FieldNode root;             // 字段树根，display name 为帧

    std::string protoLabel() const;

    // 五元组（规范化前），用于匹配与展示
    std::string endpointSrc() const;
    std::string endpointDst() const;
};

// TCP 流统计与重组状态
struct TcpStream {
    int64_t id = 0;
    std::string clientIp;
    std::string serverIp;
    uint16_t clientPort = 0;
    uint16_t serverPort = 0;
    int32_t pid = -1;
    std::string procName;

    double firstTs = 0.0;
    double lastTs = 0.0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t payloadBytes = 0;
    uint32_t retransmissions = 0;
    uint32_t outOfOrder = 0;
    uint32_t zeroWindowEvents = 0;
    bool synSeen = false;
    bool synAckSeen = false;
    bool finSeen = false;
    bool finFromClient = false;
    bool finFromServer = false;
    bool rstSeen = false;
    bool closed = false;
    double handshakeRttMs = -1.0;   // SYN -> SYN/ACK 时间差
    double durationSec = 0.0;

    // 应用层识别结果（HTTP / TLS / ...）
    std::string appProtoDetected;

    // 双向重组结果
    std::string clientToServer;
    std::string serverToClient;

    // HTTP 还原结果
    std::vector<std::string> httpRequests;
    std::vector<std::string> httpResponses;
    std::string httpHost;
    std::string httpUserAgent;

    std::string appProtocol() const;
    std::string stateLabel() const;
    std::string key() const;
};

// 协议分层统计
struct ProtoStat {
    std::string name;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

struct CaptureStats {
    uint64_t received = 0;
    uint64_t dropped = 0;
    uint64_t ifDropped = 0;
    uint64_t displayed = 0;
    uint64_t tcpPackets = 0;
    uint64_t udpPackets = 0;
    uint64_t icmpPackets = 0;
    uint64_t httpPackets = 0;
    uint64_t dnsPackets = 0;
    uint64_t malformed = 0;
};

}  // namespace nps
