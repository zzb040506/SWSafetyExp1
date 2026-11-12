// 分析流水线：抓包队列 -> 解析 -> 进程归因 -> 流重组 -> 统计
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "capture.h"
#include "process_map.h"
#include "stream_tracker.h"
#include "types.h"

namespace nps {

struct ConversationStat {
    std::string a;
    std::string b;
    std::string proto;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

class Analyzer {
public:
    Analyzer();
    ~Analyzer();

    void reset();
    void setLinkType(int linkType) { linkType_ = linkType; }
    int linkType() const { return linkType_; }
    void setProcessAttribution(bool enabled);
    void setProcessRefreshInterval(double seconds) { processRefreshSec_ = seconds; }

    void enqueue(RawPacket&& packet);
    void processPending();  // 同步处理完队列（离线分析用）
    void start();
    void stop();
    void waitIdle();

    size_t packetCount() const;
    uint64_t droppedInQueue() const;

    // 读取时必须持有 lock()
    std::unique_lock<std::mutex> lock() const { return std::unique_lock<std::mutex>(mutex_); }
    const std::deque<Packet>& packetsUnlocked() const { return packets_; }
    CaptureStats statsUnlocked() const { return stats_; }
    std::vector<TcpStream> streamsUnlocked() const { return tracker_.snapshot(); }
    std::vector<TcpEvent> streamEventsUnlocked(int64_t id) const { return tracker_.events(id); }
    std::string reassembledUnlocked(int64_t id, bool fromClient) const {
        return tracker_.reassembled(id, fromClient);
    }
    std::vector<std::pair<std::string, ProtoStat>> hierarchyUnlocked() const;
    std::vector<ConversationStat> conversationsUnlocked() const;
    size_t streamCountUnlocked() const { return tracker_.streamCount(); }
    std::vector<ProcessConn> processConnectionsUnlocked() const {
        return processMap_.connections();
    }
    std::string processStatusUnlocked() const { return processMap_.status(); }

    std::string processStatus() const;
    void refreshProcesses();

private:
    void workerLoop();
    void processOne(RawPacket&& raw);
    void accountProtocols(const Packet& p);

    mutable std::mutex mutex_;
    std::deque<Packet> packets_;
    std::deque<RawPacket> queue_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    int linkType_ = 1;
    int64_t counter_ = 0;
    uint64_t dropped_ = 0;
    CaptureStats stats_;
    StreamTracker tracker_;
    ProcessMap processMap_;
    bool attribution_ = false;
    double processRefreshSec_ = 2.0;
    double lastProcessRefresh_ = 0.0;
    std::map<std::string, ProtoStat> hierarchy_;
    std::map<std::string, ConversationStat> conversations_;
};

}  // namespace nps
