#include "stream_tracker.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "dissector.h"
#include "util.h"

namespace nps {
namespace {

constexpr size_t kMaxHttpMessages = 200;
constexpr size_t kMaxHttpTextBytes = 4096;
constexpr size_t kMaxPendingSegments = 4096;

std::string headerValue(const std::string& head, const std::string& name) {
    const std::string key = name + ":";
    size_t pos = 0;
    while (pos < head.size()) {
        const size_t e = head.find("\r\n", pos);
        const std::string line =
            head.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
        if (line.size() > key.size() &&
            containsNoCase(line.substr(0, key.size()), key)) {
            std::string v = line.substr(key.size());
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.erase(v.begin());
            while (!v.empty() && (v.back() == '\r' || v.back() == ' ')) v.pop_back();
            return v;
        }
        if (e == std::string::npos) break;
        pos = e + 2;
    }
    return std::string();
}

// 解析 chunked 编码长度；返回报文结束位置（相对 buf），解析不全返回 std::string::npos
size_t chunkedEnd(const std::string& buf, size_t bodyStart) {
    size_t pos = bodyStart;
    int guard = 0;
    while (pos < buf.size() && guard++ < 100000) {
        const size_t lineEnd = buf.find("\r\n", pos);
        if (lineEnd == std::string::npos) return std::string::npos;
        const std::string sizeLine = buf.substr(pos, lineEnd - pos);
        const size_t semi = sizeLine.find(';');
        const std::string hex = (semi == std::string::npos) ? sizeLine : sizeLine.substr(0, semi);
        char* endPtr = nullptr;
        const unsigned long long size = std::strtoull(hex.c_str(), &endPtr, 16);
        if (endPtr == hex.c_str()) return std::string::npos;
        pos = lineEnd + 2;
        if (size == 0) {
            // 跳过 trailer
            const size_t trailerEnd = buf.find("\r\n", pos);
            if (trailerEnd == std::string::npos) return std::string::npos;
            return trailerEnd + 2;
        }
        if (pos + size + 2 > buf.size()) return std::string::npos;
        pos += static_cast<size_t>(size) + 2;
    }
    return std::string::npos;
}

}  // namespace

StreamTracker::StreamTracker() = default;

void StreamTracker::reset() {
    index_.clear();
    entries_.clear();
    nextId_ = 0;
}

std::string StreamTracker::canonicalKey(const Packet& p) {
    const std::string a = p.srcAddr + ":" + std::to_string(p.srcPort);
    const std::string b = p.dstAddr + ":" + std::to_string(p.dstPort);
    return (a < b) ? (a + "|" + b) : (b + "|" + a);
}

void StreamTracker::process(Packet& p) {
    if (p.l4 != L4Proto::Tcp || !p.hasL3) return;

    const std::string key = canonicalKey(p);
    auto it = index_.find(key);
    if (it == index_.end()) {
        Entry e;
        e.stream.id = nextId_++;
        e.stream.firstTs = p.ts;
        e.stream.lastTs = p.ts;
        // 端口启发：先假设端口较大的一端是客户端
        const bool srcIsClient = (p.srcPort >= p.dstPort);
        if (p.tcpFlags & TcpFlags::Syn && !(p.tcpFlags & TcpFlags::Ack)) {
            e.clientKnown = true;
            e.stream.clientIp = p.srcAddr;
            e.stream.clientPort = p.srcPort;
            e.stream.serverIp = p.dstAddr;
            e.stream.serverPort = p.dstPort;
            e.synTime = p.ts;
        } else if (srcIsClient) {
            e.stream.clientIp = p.srcAddr;
            e.stream.clientPort = p.srcPort;
            e.stream.serverIp = p.dstAddr;
            e.stream.serverPort = p.dstPort;
        } else {
            e.stream.clientIp = p.dstAddr;
            e.stream.clientPort = p.dstPort;
            e.stream.serverIp = p.srcAddr;
            e.stream.serverPort = p.srcPort;
        }
        index_[key] = static_cast<int64_t>(entries_.size());
        entries_.push_back(std::move(e));
        it = index_.find(key);
    }

    Entry& e = entries_[it->second];
    TcpStream& s = e.stream;
    s.lastTs = p.ts;
    s.packets++;
    s.bytes += p.origlen;
    s.payloadBytes += p.payloadLength;
    if (p.pid >= 0) {
        s.pid = p.pid;
        s.procName = p.procName;
    }

    if (p.window == 0) s.zeroWindowEvents++;

    // 通过 SYN/SYN-ACK 修正客户端方向并计算握手 RTT
    if ((p.tcpFlags & TcpFlags::Syn) && !(p.tcpFlags & TcpFlags::Ack) && !s.synSeen) {
        s.synSeen = true;
        e.clientKnown = true;
        s.clientIp = p.srcAddr;
        s.clientPort = p.srcPort;
        s.serverIp = p.dstAddr;
        s.serverPort = p.dstPort;
        e.synTime = p.ts;
    }
    if ((p.tcpFlags & TcpFlags::Syn) && (p.tcpFlags & TcpFlags::Ack) && !s.synAckSeen) {
        s.synAckSeen = true;
        if (!e.clientKnown) {
            e.clientKnown = true;
            s.clientIp = p.dstAddr;
            s.clientPort = p.dstPort;
            s.serverIp = p.srcAddr;
            s.serverPort = p.srcPort;
        }
        if (e.synTime >= 0 && p.ts >= e.synTime) {
            s.handshakeRttMs = (p.ts - e.synTime) * 1000.0;
        }
    }
    if (p.tcpFlags & TcpFlags::Fin) {
        s.finSeen = true;
        if (p.srcAddr == s.clientIp && p.srcPort == s.clientPort) s.finFromClient = true;
        else s.finFromServer = true;
    }
    if (p.tcpFlags & TcpFlags::Rst) {
        s.rstSeen = true;
        s.closed = true;
    }
    if (s.finFromClient && s.finFromServer) s.closed = true;

    const bool srcIsClient = (p.srcAddr == s.clientIp && p.srcPort == s.clientPort);
    Direction& dir = srcIsClient ? e.fromClient : e.fromServer;

    // SYN 占一个序号
    if ((p.tcpFlags & TcpFlags::Syn) && !dir.initialized) {
        dir.initialized = true;
        dir.baseSeq = p.seq + 1;
    }

    bool retrans = false;
    bool ooo = false;
    if (p.payloadLength > 0) {
        if (!dir.initialized) {
            dir.initialized = true;
            dir.baseSeq = p.seq;
        }
        const int64_t rel = static_cast<int32_t>(p.seq - dir.baseSeq);
        handlePayload(e, dir, p, rel, retrans, ooo);
    }
    p.retransmission = retrans;
    p.outOfOrder = ooo;
    if (retrans) s.retransmissions++;
    if (ooo) s.outOfOrder++;
    p.streamId = s.id;

    detectAppProto(e);
}

void StreamTracker::handlePayload(Entry& e, Direction& dir, const Packet& p, int64_t rel,
                                  bool& retrans, bool& ooo) {
    const uint8_t* data = p.raw.data() + p.payloadOffset;
    const size_t len = p.payloadLength;
    if (p.payloadOffset + len > p.raw.size()) return;

    auto appendAt = [&](size_t off, const uint8_t* src, size_t n) {
        if (dir.data.size() >= kMaxRetainedBytes) {
            dir.capped = true;
            return;
        }
        const size_t room = kMaxRetainedBytes - dir.data.size();
        const size_t take = std::min(n, room);
        (void)off;
        dir.data.append(reinterpret_cast<const char*>(src), take);
        if (take < n) dir.capped = true;
    };

    const int64_t endRel = rel + static_cast<int64_t>(len);

    // 重组缓冲已封顶：改用“已见最高序号”判定，避免把后续正常报文全部误报为乱序
    if (dir.capped) {
        if (endRel <= dir.maxEnd) {
            retrans = true;
        } else if (rel > dir.maxEnd) {
            ooo = true;
        } else {
            dir.maxEnd = endRel;
        }
        return;
    }

    if (rel < 0) {
        retrans = true;
        return;
    }
    const size_t r = static_cast<size_t>(rel);
    if (endRel > dir.maxEnd) dir.maxEnd = endRel;
    if (r < dir.data.size()) {
        const size_t overlap = dir.data.size() - r;
        if (len <= overlap) {
            retrans = true;
            // 仍可能是部分重叠的新数据，这里已全部被覆盖
            return;
        }
        retrans = true;
        appendAt(dir.data.size(), data + overlap, len - overlap);
    } else if (r == dir.data.size()) {
        appendAt(dir.data.size(), data, len);
    } else {
        ooo = true;
        if (dir.pending.size() < kMaxPendingSegments) {
            dir.pending[r] = std::vector<uint8_t>(data, data + len);
        }
        return;
    }

    // 填补空洞
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto it = dir.pending.begin(); it != dir.pending.end();) {
            const size_t start = static_cast<size_t>(it->first);
            if (start > dir.data.size()) break;
            const std::vector<uint8_t>& seg = it->second;
            if (start == dir.data.size()) {
                appendAt(dir.data.size(), seg.data(), seg.size());
                it = dir.pending.erase(it);
                progress = true;
            } else {
                const size_t ov = dir.data.size() - start;
                if (ov < seg.size()) {
                    appendAt(dir.data.size(), seg.data() + ov, seg.size() - ov);
                    progress = true;
                }
                it = dir.pending.erase(it);
            }
        }
    }

    // HTTP 增量解析
    const bool fromClient = (&dir == &e.fromClient);
    if (dir.httpParsePos == 0 && dir.data.size() >= 4) {
        const bool http = Dissector::looksLikeHttp(
            reinterpret_cast<const uint8_t*>(dir.data.data()),
            std::min<size_t>(dir.data.size(), 16));
        if (http) {
            parseHttpMessages(e, dir, fromClient);
        }
    } else if (dir.httpParsePos > 0) {
        parseHttpMessages(e, dir, fromClient);
    }
}

void StreamTracker::parseHttpMessages(Entry& e, Direction& dir, bool fromClient) {
    const std::string& buf = dir.data;
    while (dir.httpParsePos < buf.size() && dir.messages < kMaxHttpMessages) {
        const size_t start = dir.httpParsePos;
        const size_t hdrEnd = buf.find("\r\n\r\n", start);
        if (hdrEnd == std::string::npos) break;
        const std::string head = buf.substr(start, hdrEnd - start);

        bool isRequest = false;
        bool isResponse = false;
        if (head.rfind("HTTP/", 0) == 0) {
            isResponse = true;
        } else {
            static const char* kMethods[] = {"GET",     "POST",  "HEAD", "PUT",    "DELETE",
                                             "OPTIONS", "PATCH", "TRACE", "CONNECT"};
            for (const char* m : kMethods) {
                if (head.rfind(m, 0) == 0 && head.size() > std::strlen(m) &&
                    head[std::strlen(m)] == ' ') {
                    isRequest = true;
                    break;
                }
            }
        }
        if (!isRequest && !isResponse) break;

        const size_t bodyStart = hdrEnd + 4;
        size_t msgEnd = bodyStart;
        const std::string te = headerValue(head, "Transfer-Encoding");
        const std::string cl = headerValue(head, "Content-Length");
        bool hasBody = true;
        if (isResponse) {
            const size_t sp = head.find(' ');
            if (sp != std::string::npos && sp + 4 <= head.size()) {
                const std::string code = head.substr(sp + 1, 3);
                if (code == "204" || code == "304" || code == "101") hasBody = false;
            }
        }
        if (!hasBody) {
            msgEnd = bodyStart;
        } else if (containsNoCase(te, "chunked")) {
            const size_t end = chunkedEnd(buf, bodyStart);
            if (end == std::string::npos) break;  // 等待更多数据
            msgEnd = end;
        } else if (!cl.empty()) {
            char* endPtr = nullptr;
            const unsigned long long n = std::strtoull(cl.c_str(), &endPtr, 10);
            if (endPtr == cl.c_str()) break;
            if (bodyStart + n > buf.size()) break;
            msgEnd = bodyStart + static_cast<size_t>(n);
        } else {
            msgEnd = bodyStart;
        }

        std::string text = buf.substr(start, std::min<size_t>(msgEnd - start, kMaxHttpTextBytes));
        std::string summary;
        if (isRequest) {
            const size_t sp1 = head.find(' ');
            const size_t sp2 = head.find(' ', sp1 + 1);
            const std::string method = head.substr(0, sp1);
            const std::string uri =
                (sp1 != std::string::npos && sp2 != std::string::npos)
                    ? head.substr(sp1 + 1, sp2 - sp1 - 1)
                    : std::string();
            const std::string host = headerValue(head, "Host");
            summary = method + " " + uri + (host.empty() ? "" : ("  Host: " + host));
            if (e.stream.httpHost.empty() && !host.empty()) e.stream.httpHost = host;
            const std::string ua = headerValue(head, "User-Agent");
            if (e.stream.httpUserAgent.empty() && !ua.empty()) e.stream.httpUserAgent = ua;
            e.stream.httpRequests.push_back(text);
            if (e.stream.httpRequests.size() > kMaxHttpMessages) e.stream.httpRequests.erase(
                e.stream.httpRequests.begin());
        } else {
            const size_t sp = head.find(' ');
            const std::string code = (sp != std::string::npos) ? head.substr(sp + 1, 3) : "";
            const std::string reason =
                (sp != std::string::npos && head.find(' ', sp + 1) != std::string::npos)
                    ? head.substr(head.find(' ', sp + 1) + 1)
                    : std::string();
            summary = "HTTP/1.x " + code + " " + reason;
            e.stream.httpResponses.push_back(text);
            if (e.stream.httpResponses.size() > kMaxHttpMessages) e.stream.httpResponses.erase(
                e.stream.httpResponses.begin());
        }
        (void)summary;
        dir.httpParsePos = msgEnd;
        dir.messages++;
    }
}

void StreamTracker::detectAppProto(Entry& e) {
    if (!e.stream.appProtoDetected.empty()) return;
    const std::string& up = e.fromClient.data;
    const std::string& down = e.fromServer.data;
    if (!e.stream.httpRequests.empty() || !e.stream.httpResponses.empty()) {
        e.stream.appProtoDetected = "HTTP";
        return;
    }
    auto startsWithTls = [](const std::string& s) {
        return s.size() >= 3 && static_cast<uint8_t>(s[0]) == 0x16 &&
               static_cast<uint8_t>(s[1]) == 0x03;
    };
    if (startsWithTls(up) || startsWithTls(down)) {
        e.stream.appProtoDetected = "TLS";
    }
}

std::vector<TcpStream> StreamTracker::snapshot() const {
    std::vector<TcpStream> out;
    out.reserve(entries_.size());
    for (const Entry& e : entries_) {
        TcpStream s = e.stream;
        s.clientToServer = e.fromClient.data;
        s.serverToClient = e.fromServer.data;
        s.durationSec = s.lastTs - s.firstTs;
        out.push_back(std::move(s));
    }
    return out;
}

const TcpStream* StreamTracker::find(int64_t id) const {
    for (const Entry& e : entries_) {
        if (e.stream.id == id) return &e.stream;
    }
    return nullptr;
}

std::string StreamTracker::reassembled(int64_t id, bool fromClient) const {
    for (const Entry& e : entries_) {
        if (e.stream.id == id) return fromClient ? e.fromClient.data : e.fromServer.data;
    }
    return std::string();
}

}  // namespace nps
