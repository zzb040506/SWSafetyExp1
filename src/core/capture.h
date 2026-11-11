// libpcap 抓包封装：实时抓包、离线读取、BPF 过滤、PCAP 导出
#pragma once

#include <pcap.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "types.h"

namespace nps {

struct RawPacket {
    double ts = 0.0;
    uint32_t caplen = 0;
    uint32_t origlen = 0;
    std::vector<uint8_t> data;
};

using PacketSink = std::function<void(RawPacket&&)>;

class CaptureEngine {
public:
    struct DeviceInfo {
        std::string name;
        std::string description;
        bool loopback = false;
    };

    CaptureEngine();
    ~CaptureEngine();

    static std::vector<DeviceInfo> listDevices(std::string& error);

    bool openLive(const std::string& device, std::string& error);
    bool openOffline(const std::string& path, std::string& error);
    bool setBpfFilter(const std::string& expression, std::string& error);
    bool startLive(std::string& error);
    void stop();
    bool running() const { return running_.load(); }
    int linkType() const { return linkType_; }

    // 同步读取离线文件全部报文
    void readOfflineAll(const PacketSink& sink);

    void setSink(PacketSink sink);

    // 抓包同时写 pcap 文件
    bool startDump(const std::string& path, std::string& error);
    void stopDump();

    CaptureStats pcapStats() const;
    std::string lastError() const;
    bool isOpen() const { return handle_ != nullptr; }

private:
    static void packetThunk(unsigned char* user, const struct pcap_pkthdr* hdr,
                            const unsigned char* data);
    void emit(const struct pcap_pkthdr* hdr, const unsigned char* data);
    void closeHandle();

    pcap_t* handle_ = nullptr;
    pcap_dumper* dumper_ = nullptr;
    std::thread thread_;
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    PacketSink sink_;
    int linkType_ = 1;
    uint64_t offlineCount_ = 0;
    std::string error_;
};

}  // namespace nps
