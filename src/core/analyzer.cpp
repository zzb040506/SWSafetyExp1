#include "analyzer.h"

#include <chrono>
#include <cstring>

#include "dissector.h"
#include "util.h"

namespace nps {
namespace {

std::string joinPath(const std::vector<std::string>& parts, size_t n) {
    std::string out;
    for (size_t i = 0; i < n && i < parts.size(); ++i) {
        if (i) out += "|";
        out += parts[i];
    }
    return out;
}

}  // namespace

Analyzer::Analyzer() = default;

Analyzer::~Analyzer() { stop(); }

void Analyzer::reset() {
    stop();
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.clear();
    queue_.clear();
    counter_ = 0;
    dropped_ = 0;
    stats_ = CaptureStats();
    tracker_.reset();
    hierarchy_.clear();
    conversations_.clear();
    lastProcessRefresh_ = 0.0;
}

void Analyzer::setProcessAttribution(bool enabled) {
    attribution_ = enabled;
    if (enabled) refreshProcesses();
}

void Analyzer::refreshProcesses() {
    ProcessMap snapshot;
    snapshot.refresh();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        processMap_ = std::move(snapshot);
        lastProcessRefresh_ = static_cast<double>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count()) /
            1000.0;
    }
}

std::string Analyzer::processStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return processMap_.status();
}

void Analyzer::enqueue(RawPacket&& packet) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() > 500000) {
            ++dropped_;
            return;
        }
        queue_.push_back(std::move(packet));
    }
    cv_.notify_one();
}

void Analyzer::start() {
    if (running_.load()) return;
    stopping_.store(false);
    running_.store(true);
    worker_ = std::thread([this]() { workerLoop(); });
}

void Analyzer::stop() {
    if (!running_.load() && !worker_.joinable()) return;
    stopping_.store(true);
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    running_.store(false);
    stopping_.store(false);
}

void Analyzer::waitIdle() {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty()) return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

size_t Analyzer::packetCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_.size();
}

uint64_t Analyzer::droppedInQueue() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

void Analyzer::workerLoop() {
    while (!stopping_.load()) {
        std::deque<RawPacket> batch;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(50),
                         [this]() { return stopping_.load() || !queue_.empty(); });
            if (!queue_.empty()) {
                const size_t take = std::min<size_t>(queue_.size(), 4096);
                for (size_t i = 0; i < take; ++i) {
                    batch.push_back(std::move(queue_.front()));
                    queue_.pop_front();
                }
            }
        }
        for (auto& raw : batch) processOne(std::move(raw));
        if (batch.empty()) {
            // 周期性刷新进程表
            if (attribution_) {
                const double now = static_cast<double>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count()) /
                    1000.0;
                double last = 0.0;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    last = lastProcessRefresh_;
                }
                if (now - last > processRefreshSec_) refreshProcesses();
            }
            if (stopping_.load()) break;
        }
    }
}

void Analyzer::processPending() {
    std::deque<RawPacket> batch;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        batch.swap(queue_);
    }
    for (auto& raw : batch) processOne(std::move(raw));
}

void Analyzer::processOne(RawPacket&& raw) {
    Packet p;
    p.index = ++counter_;
    p.ts = raw.ts;
    p.caplen = raw.caplen;
    p.origlen = raw.origlen;
    p.raw = std::move(raw.data);
    Dissector::dissect(p, linkType_);

    if (attribution_ && p.l4 == L4Proto::Tcp) {
        int32_t pid = -1;
        std::string name;
        if (processMap_.lookup(p.srcAddr, p.srcPort, p.dstAddr, p.dstPort, pid, name)) {
            p.pid = pid;
            p.procName = name;
        }
    }

    tracker_.process(p);

    std::lock_guard<std::mutex> lock(mutex_);
    if (p.malformed) stats_.malformed++;
    switch (p.l4) {
        case L4Proto::Tcp: stats_.tcpPackets++; break;
        case L4Proto::Udp: stats_.udpPackets++; break;
        case L4Proto::Icmp:
        case L4Proto::Icmpv6: stats_.icmpPackets++; break;
        default: break;
    }
    if (p.appProto == "HTTP") stats_.httpPackets++;
    if (p.appProto == "DNS") stats_.dnsPackets++;
    accountProtocols(p);
    packets_.push_back(std::move(p));
}

void Analyzer::accountProtocols(const Packet& p) {
    std::vector<std::string> path;
    path.push_back("Frame");
    if (p.hasEth) path.push_back("Ethernet II");
    switch (p.l3) {
        case L3Proto::Arp: path.push_back("ARP"); break;
        case L3Proto::IPv4: path.push_back("IPv4"); break;
        case L3Proto::IPv6: path.push_back("IPv6"); break;
        default: break;
    }
    switch (p.l4) {
        case L4Proto::Tcp: path.push_back("TCP"); break;
        case L4Proto::Udp: path.push_back("UDP"); break;
        case L4Proto::Icmp: path.push_back("ICMP"); break;
        case L4Proto::Icmpv6: path.push_back("ICMPv6"); break;
        default: break;
    }
    if (p.appProto == "HTTP" || p.appProto == "DNS" || p.appProto == "TLS") {
        path.push_back(p.appProto);
    }
    for (size_t i = 1; i <= path.size(); ++i) {
        ProtoStat& s = hierarchy_[joinPath(path, i)];
        s.name = joinPath(path, i);
        s.packets++;
        s.bytes += p.origlen;
    }

    if (p.l4 == L4Proto::Tcp || p.l4 == L4Proto::Udp) {
        std::string a = p.srcAddr + ":" + std::to_string(p.srcPort);
        std::string b = p.dstAddr + ":" + std::to_string(p.dstPort);
        if (b < a) std::swap(a, b);
        const std::string key = a + "|" + b;
        ConversationStat& c = conversations_[key];
        c.a = a;
        c.b = b;
        c.proto = (p.l4 == L4Proto::Tcp) ? "TCP" : "UDP";
        c.packets++;
        c.bytes += p.origlen;
    }
}

std::vector<std::pair<std::string, ProtoStat>> Analyzer::hierarchyUnlocked() const {
    std::vector<std::pair<std::string, ProtoStat>> out;
    out.reserve(hierarchy_.size());
    for (const auto& kv : hierarchy_) out.emplace_back(kv.first, kv.second);
    return out;
}

std::vector<ConversationStat> Analyzer::conversationsUnlocked() const {
    std::vector<ConversationStat> out;
    out.reserve(conversations_.size());
    for (const auto& kv : conversations_) out.push_back(kv.second);
    return out;
}

}  // namespace nps
