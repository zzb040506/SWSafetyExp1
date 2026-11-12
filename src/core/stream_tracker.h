// TCP 流追踪与重组：五元组归并、乱序/重传检测、HTTP 报文还原
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "types.h"

namespace nps {

class StreamTracker {
public:
    StreamTracker();

    void reset();
    // 处理一条已解析报文，回填 streamId / retransmission / outOfOrder
    void process(Packet& p);

    std::vector<TcpStream> snapshot() const;
    const TcpStream* find(int64_t id) const;
    size_t streamCount() const { return entries_.size(); }

    // 流内字节（用于 GUI 展示），最多保留 kMaxRetainedBytes
    std::string reassembled(int64_t id, bool fromClient) const;

    static constexpr size_t kMaxRetainedBytes = 512 * 1024;

private:
    struct Direction {
        bool initialized = false;
        uint32_t baseSeq = 0;  // 数据起始序号
        std::string data;      // 已按序重组的数据
        std::map<int64_t, std::vector<uint8_t>> pending;  // 缺口后的乱序段
        uint64_t payloadBytes = 0;
        size_t httpParsePos = 0;
        size_t messages = 0;
        bool capped = false;
        int64_t maxEnd = 0;  // 已见数据的最高相对序号；缓冲区封顶后用它继续判定乱序/重传
    };

    struct Entry {
        TcpStream stream;
        Direction fromClient;
        Direction fromServer;
        bool clientKnown = false;
        double synTime = -1.0;
    };

    static std::string canonicalKey(const Packet& p);
    void handlePayload(Entry& e, Direction& dir, const Packet& p, int64_t relSeen, bool& retrans,
                       bool& ooo);
    void parseHttpMessages(Entry& e, Direction& dir, bool fromClient);
    void detectAppProto(Entry& e);

    std::map<std::string, int64_t> index_;
    std::vector<Entry> entries_;
    int64_t nextId_ = 0;
};

}  // namespace nps
