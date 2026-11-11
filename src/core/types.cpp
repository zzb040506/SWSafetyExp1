#include "types.h"

#include "util.h"

namespace nps {

std::string Packet::protoLabel() const {
    if (appProto == "HTTP" || appProto == "DNS" || appProto == "TLS" || appProto == "ARP" ||
        appProto == "ICMP" || appProto == "ICMPv6") {
        return appProto;
    }
    switch (l4) {
        case L4Proto::Tcp: return "TCP";
        case L4Proto::Udp: return "UDP";
        case L4Proto::Icmp: return "ICMP";
        case L4Proto::Icmpv6: return "ICMPv6";
        default: break;
    }
    switch (l3) {
        case L3Proto::Arp: return "ARP";
        case L3Proto::IPv4: return "IPv4";
        case L3Proto::IPv6: return "IPv6";
        default: break;
    }
    return "Unknown";
}

std::string Packet::endpointSrc() const {
    if (l4 == L4Proto::Tcp || l4 == L4Proto::Udp) {
        return srcAddr + ":" + std::to_string(srcPort);
    }
    return srcAddr;
}

std::string Packet::endpointDst() const {
    if (l4 == L4Proto::Tcp || l4 == L4Proto::Udp) {
        return dstAddr + ":" + std::to_string(dstPort);
    }
    return dstAddr;
}

std::string TcpStream::appProtocol() const {
    if (!appProtoDetected.empty()) return appProtoDetected;
    return "TCP";
}

std::string TcpStream::stateLabel() const {
    if (rstSeen) return "RST";
    if (closed) return "CLOSED";
    if (finSeen) return "FIN_WAIT";
    if (synSeen && synAckSeen) return "ESTABLISHED";
    if (synSeen) return "SYN_SENT";
    return "MIDSTREAM";
}

std::string TcpStream::key() const {
    return clientIp + ":" + std::to_string(clientPort) + " \u2192 " + serverIp + ":" +
           std::to_string(serverPort);
}

}  // namespace nps
