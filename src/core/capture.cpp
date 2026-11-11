#include "capture.h"

#include <pcap.h>

#include <chrono>
#include <cstring>

namespace nps {
namespace {

double timevalToDouble(const struct timeval& tv) {
    return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1000000.0;
}

std::string pcapErrorText(const char* prefix, const std::string& detail) {
    if (detail.empty()) return prefix;
    return std::string(prefix) + ": " + detail;
}

}  // namespace

CaptureEngine::CaptureEngine() = default;

CaptureEngine::~CaptureEngine() {
    stop();
    stopDump();
    closeHandle();
}

std::vector<CaptureEngine::DeviceInfo> CaptureEngine::listDevices(std::string& error) {
    std::vector<DeviceInfo> result;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devs = nullptr;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        error = pcapErrorText("枚举网卡失败", errbuf);
        return result;
    }
    for (pcap_if_t* d = devs; d != nullptr; d = d->next) {
        DeviceInfo info;
        info.name = d->name ? d->name : "";
        info.description = d->description ? d->description : "";
        info.loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
        result.push_back(std::move(info));
    }
    pcap_freealldevs(devs);
    return result;
}

void CaptureEngine::closeHandle() {
    if (dumper_) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool CaptureEngine::openLive(const std::string& device, std::string& error) {
    stop();
    closeHandle();
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_create(device.c_str(), errbuf);
    if (!handle_) {
        error = pcapErrorText("打开网卡失败", errbuf);
        return false;
    }
    pcap_set_snaplen(handle_, 262144);
    pcap_set_promisc(handle_, 1);
    pcap_set_timeout(handle_, 100);
    pcap_set_buffer_size(handle_, 16 * 1024 * 1024);
    pcap_set_immediate_mode(handle_, 1);

    const int rc = pcap_activate(handle_);
    if (rc < 0) {
        error = pcapErrorText("激活网卡失败", pcap_geterr(handle_));
        closeHandle();
        return false;
    }
    if (rc > 0) {
        // 警告（如不支持混杂模式）不阻断抓包
        error = pcapErrorText("激活网卡警告", pcap_statustostr(rc));
    }
    linkType_ = pcap_datalink(handle_);
    offlineCount_ = 0;
    return true;
}

bool CaptureEngine::openOffline(const std::string& path, std::string& error) {
    stop();
    closeHandle();
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(path.c_str(), errbuf);
    if (!handle_) {
        error = pcapErrorText("打开 pcap 文件失败", errbuf);
        return false;
    }
    linkType_ = pcap_datalink(handle_);
    offlineCount_ = 0;
    return true;
}

bool CaptureEngine::setBpfFilter(const std::string& expression, std::string& error) {
    if (!handle_) {
        error = "尚未打开抓包句柄";
        return false;
    }
    if (expression.find_first_not_of(" \t\r\n") == std::string::npos) {
        struct bpf_program empty;
        std::memset(&empty, 0, sizeof(empty));
        pcap_setfilter(handle_, nullptr);
        return true;
    }
    struct bpf_program prog;
    std::memset(&prog, 0, sizeof(prog));
    if (pcap_compile(handle_, &prog, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        error = pcapErrorText("BPF 表达式编译失败", pcap_geterr(handle_));
        return false;
    }
    if (pcap_setfilter(handle_, &prog) != 0) {
        error = pcapErrorText("安装 BPF 过滤器失败", pcap_geterr(handle_));
        pcap_freecode(&prog);
        return false;
    }
    pcap_freecode(&prog);
    return true;
}

void CaptureEngine::setSink(PacketSink sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = std::move(sink);
}

void CaptureEngine::packetThunk(unsigned char* user, const struct pcap_pkthdr* hdr,
                                const unsigned char* data) {
    auto* self = reinterpret_cast<CaptureEngine*>(user);
    self->emit(hdr, data);
}

void CaptureEngine::emit(const struct pcap_pkthdr* hdr, const unsigned char* data) {
    RawPacket pkt;
    pkt.ts = timevalToDouble(hdr->ts);
    pkt.caplen = hdr->caplen;
    pkt.origlen = hdr->len;
    pkt.data.assign(data, data + hdr->caplen);

    if (dumper_) {
        pcap_dump(reinterpret_cast<u_char*>(dumper_), hdr, data);
    }
    PacketSink sink;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sink = sink_;
    }
    if (sink) sink(std::move(pkt));
}

bool CaptureEngine::startLive(std::string& error) {
    if (!handle_) {
        error = "尚未打开网卡";
        return false;
    }
    if (running_.load()) {
        error = "抓包已在进行中";
        return false;
    }
    running_.store(true);
    thread_ = std::thread([this]() {
        const int rc = pcap_loop(handle_, -1, &CaptureEngine::packetThunk,
                                 reinterpret_cast<u_char*>(this));
        if (rc == -1) {
            std::lock_guard<std::mutex> lock(mutex_);
            error_ = pcapErrorText("抓包线程异常", pcap_geterr(handle_));
        }
        running_.store(false);
    });
    return true;
}

void CaptureEngine::stop() {
    if (thread_.joinable()) {
        if (handle_) pcap_breakloop(handle_);
        thread_.join();
    }
    running_.store(false);
}

void CaptureEngine::readOfflineAll(const PacketSink& sink) {
    if (!handle_) return;
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;
    int rc = 0;
    while ((rc = pcap_next_ex(handle_, &hdr, &data)) == 1) {
        ++offlineCount_;
        if (hdr && data) {
            // 离线模式不写 dump，避免重复写
            RawPacket pkt;
            pkt.ts = timevalToDouble(hdr->ts);
            pkt.caplen = hdr->caplen;
            pkt.origlen = hdr->len;
            pkt.data.assign(data, data + hdr->caplen);
            if (sink) sink(std::move(pkt));
        }
    }
    if (rc == -1) {
        std::lock_guard<std::mutex> lock(mutex_);
        error_ = pcapErrorText("读取 pcap 文件失败", pcap_geterr(handle_));
    }
}

bool CaptureEngine::startDump(const std::string& path, std::string& error) {
    if (!handle_) {
        error = "尚未打开抓包句柄";
        return false;
    }
    stopDump();
    dumper_ = pcap_dump_open(handle_, path.c_str());
    if (!dumper_) {
        error = pcapErrorText("创建 pcap 文件失败", pcap_geterr(handle_));
        return false;
    }
    return true;
}

void CaptureEngine::stopDump() {
    if (dumper_) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
    }
}

CaptureStats CaptureEngine::pcapStats() const {
    CaptureStats stats;
    stats.received = offlineCount_;
    if (handle_) {
        struct pcap_stat ps;
        std::memset(&ps, 0, sizeof(ps));
        if (pcap_stats(handle_, &ps) == 0) {
            stats.received = std::max<uint64_t>(stats.received, ps.ps_recv);
            stats.dropped = ps.ps_drop;
            stats.ifDropped = ps.ps_ifdrop;
        }
    }
    return stats;
}

std::string CaptureEngine::lastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return error_;
}

}  // namespace nps
