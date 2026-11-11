// 命令行分析入口：离线 pcap 分析、实时抓包、统计导出（GUI 之外的可复现实验通道）
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "core/analyzer.h"
#include "core/capture.h"
#include "core/dissector.h"
#include "core/filter.h"
#include "core/process_map.h"
#include "core/util.h"

namespace {

void printUsage() {
    std::printf(
        "NPS Sniffer CLI - 网络嗅探与协议分析\n"
        "用法:\n"
        "  nps-cli --list-devices\n"
        "  nps-cli --read <file.pcap> [选项]\n"
        "  nps-cli --live <device> --seconds <N> [--dump <out.pcap>] [选项]\n"
        "选项:\n"
        "  --bpf <expr>         libpcap 内核过滤器\n"
        "  --filter <expr>      显示过滤器，如 \"tcp and port == 80\"\n"
        "  --streams            打印 TCP 流表\n"
        "  --http               打印还原的 HTTP 请求/响应\n"
        "  --procs              打印进程归因结果\n"
        "  --quiet              仅打印汇总\n"
        "  --json               以 JSON 输出汇总\n");
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    std::string readPath, liveDevice, bpf, displayFilter, dumpPath;
    double seconds = 5.0;
    bool wantStreams = false, wantHttp = false, wantProcs = false, quiet = false, json = false;
    int wantPackets = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "参数 %s 缺少取值\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") {
            printUsage();
            return 0;
        } else if (a == "--list-devices") {
            std::string err;
            const auto devs = nps::CaptureEngine::listDevices(err);
            if (!err.empty()) std::fprintf(stderr, "%s\n", err.c_str());
            for (size_t i = 0; i < devs.size(); ++i) {
                std::printf("%zu. %-20s %s%s\n", i + 1, devs[i].name.c_str(),
                            devs[i].description.c_str(), devs[i].loopback ? " [loopback]" : "");
            }
            return 0;
        } else if (a == "--read") {
            readPath = next("--read");
        } else if (a == "--live") {
            liveDevice = next("--live");
        } else if (a == "--seconds") {
            seconds = std::atof(next("--seconds").c_str());
        } else if (a == "--bpf") {
            bpf = next("--bpf");
        } else if (a == "--filter") {
            displayFilter = next("--filter");
        } else if (a == "--dump") {
            dumpPath = next("--dump");
        } else if (a == "--streams") {
            wantStreams = true;
        } else if (a == "--packets") {
            wantPackets = (i + 1 < argc && argv[i + 1][0] != '-') ? std::atoi(argv[++i]) : 50;
        } else if (a == "--http") {
            wantHttp = true;
        } else if (a == "--procs") {
            wantProcs = true;
        } else if (a == "--quiet") {
            quiet = true;
        } else if (a == "--json") {
            json = true;
        } else {
            std::fprintf(stderr, "未知参数: %s\n", a.c_str());
            printUsage();
            return 2;
        }
    }

    if (readPath.empty() && liveDevice.empty()) {
        printUsage();
        return 2;
    }

    nps::Analyzer analyzer;
    nps::DisplayFilter filter;
    std::string err;
    if (!filter.compile(displayFilter, err)) {
        std::fprintf(stderr, "显示过滤器语法错误: %s\n", err.c_str());
        return 2;
    }
    analyzer.setProcessAttribution(wantProcs);

    nps::CaptureEngine capture;
    if (!readPath.empty()) {
        if (!capture.openOffline(readPath, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
        analyzer.setLinkType(capture.linkType());
        if (!bpf.empty() && !capture.setBpfFilter(bpf, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
        capture.readOfflineAll([&analyzer](nps::RawPacket&& p) { analyzer.enqueue(std::move(p)); });
        analyzer.processPending();
    } else {
        if (!capture.openLive(liveDevice, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
        if (!bpf.empty() && !capture.setBpfFilter(bpf, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
        if (!dumpPath.empty() && !capture.startDump(dumpPath, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
        analyzer.setLinkType(capture.linkType());
        analyzer.start();
        capture.setSink([&analyzer](nps::RawPacket&& p) { analyzer.enqueue(std::move(p)); });
        if (!capture.startLive(err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() <
               seconds) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        capture.stop();
        analyzer.waitIdle();
        analyzer.stop();
    }

    capture.stopDump();

    auto lk = analyzer.lock();
    const auto& packets = analyzer.packetsUnlocked();
    const nps::CaptureStats st = analyzer.statsUnlocked();
    const auto pcapStats = capture.pcapStats();
    const auto streams = analyzer.streamsUnlocked();
    const auto hierarchy = analyzer.hierarchyUnlocked();
    const auto conversations = analyzer.conversationsUnlocked();

    uint64_t visible = 0;
    uint64_t visibleBytes = 0;
    std::vector<const nps::Packet*> matched;
    for (const auto& p : packets) {
        if (filter.matches(p)) {
            ++visible;
            visibleBytes += p.origlen;
            matched.push_back(&p);
        }
    }
    uint64_t retrans = 0;
    uint64_t ooo = 0;
    for (const auto& s : streams) {
        retrans += s.retransmissions;
        ooo += s.outOfOrder;
    }

    if (json) {
        std::printf("{\n");
        std::printf("  \"file\": \"%s\",\n", jsonEscape(readPath).c_str());
        std::printf("  \"packets\": %zu,\n", packets.size());
        std::printf("  \"visible_after_display_filter\": %llu,\n",
                    static_cast<unsigned long long>(visible));
        std::printf("  \"pcap_received\": %llu,\n",
                    static_cast<unsigned long long>(pcapStats.received));
        std::printf("  \"pcap_dropped\": %llu,\n",
                    static_cast<unsigned long long>(pcapStats.dropped));
        std::printf("  \"tcp\": %llu,\n", static_cast<unsigned long long>(st.tcpPackets));
        std::printf("  \"udp\": %llu,\n", static_cast<unsigned long long>(st.udpPackets));
        std::printf("  \"icmp\": %llu,\n", static_cast<unsigned long long>(st.icmpPackets));
        std::printf("  \"http\": %llu,\n", static_cast<unsigned long long>(st.httpPackets));
        std::printf("  \"dns\": %llu,\n", static_cast<unsigned long long>(st.dnsPackets));
        std::printf("  \"malformed\": %llu,\n", static_cast<unsigned long long>(st.malformed));
        std::printf("  \"streams\": %zu,\n", streams.size());
        std::printf("  \"retransmissions\": %llu,\n", static_cast<unsigned long long>(retrans));
        std::printf("  \"out_of_order\": %llu,\n", static_cast<unsigned long long>(ooo));
        std::printf("  \"hierarchy\": [\n");
        for (size_t i = 0; i < hierarchy.size(); ++i) {
            std::printf("    {\"path\": \"%s\", \"packets\": %llu, \"bytes\": %llu}%s\n",
                        jsonEscape(hierarchy[i].first).c_str(),
                        static_cast<unsigned long long>(hierarchy[i].second.packets),
                        static_cast<unsigned long long>(hierarchy[i].second.bytes),
                        i + 1 == hierarchy.size() ? "" : ",");
        }
        std::printf("  ],\n");
        std::printf("  \"conversations\": [\n");
        for (size_t i = 0; i < conversations.size(); ++i) {
            std::printf("    {\"a\": \"%s\", \"b\": \"%s\", \"proto\": \"%s\", "
                        "\"packets\": %llu, \"bytes\": %llu}%s\n",
                        jsonEscape(conversations[i].a).c_str(),
                        jsonEscape(conversations[i].b).c_str(),
                        conversations[i].proto.c_str(),
                        static_cast<unsigned long long>(conversations[i].packets),
                        static_cast<unsigned long long>(conversations[i].bytes),
                        i + 1 == conversations.size() ? "" : ",");
        }
        std::printf("  ],\n");
        std::printf("  \"http_requests\": [\n");
        bool firstReq = true;
        for (const auto& s : streams) {
            for (const auto& r : s.httpRequests) {
                const size_t e = r.find("\r\n");
                const std::string line = r.substr(0, e == std::string::npos ? r.size() : e);
                std::printf("%s    {\"stream\": %lld, \"client\": \"%s\", \"line\": \"%s\"}",
                            firstReq ? "" : ",\n", static_cast<long long>(s.id),
                            jsonEscape(s.key()).c_str(), jsonEscape(line).c_str());
                firstReq = false;
            }
        }
        std::printf("\n  ]\n}\n");
    } else {
        std::printf("=== 汇总 ===\n");
        std::printf("报文总数        : %zu\n", packets.size());
        std::printf("显示过滤后      : %llu (%llu 字节)\n",
                    static_cast<unsigned long long>(visible),
                    static_cast<unsigned long long>(visibleBytes));
        std::printf("libpcap 收包    : %llu，丢包 %llu，网卡丢包 %llu\n",
                    static_cast<unsigned long long>(pcapStats.received),
                    static_cast<unsigned long long>(pcapStats.dropped),
                    static_cast<unsigned long long>(pcapStats.ifDropped));
        std::printf("TCP/UDP/ICMP    : %llu / %llu / %llu\n",
                    static_cast<unsigned long long>(st.tcpPackets),
                    static_cast<unsigned long long>(st.udpPackets),
                    static_cast<unsigned long long>(st.icmpPackets));
        std::printf("HTTP/DNS        : %llu / %llu\n",
                    static_cast<unsigned long long>(st.httpPackets),
                    static_cast<unsigned long long>(st.dnsPackets));
        std::printf("TCP 流          : %zu（重传 %llu，乱序 %llu）\n", streams.size(),
                    static_cast<unsigned long long>(retrans),
                    static_cast<unsigned long long>(ooo));
        std::printf("畸形报文        : %llu\n",
                    static_cast<unsigned long long>(st.malformed));

        if (!quiet) {
            std::printf("\n=== 协议分层 ===\n");
            for (const auto& h : hierarchy) {
                int depth = 0;
                for (char c : h.first)
                    if (c == '|') ++depth;
                std::string leaf = h.first;
                const size_t bar = leaf.rfind('|');
                if (bar != std::string::npos) leaf = leaf.substr(bar + 1);
                std::printf("%*s%-18s %8llu 报文  %10s\n", depth * 2, "", leaf.c_str(),
                            static_cast<unsigned long long>(h.second.packets),
                            nps::formatBytes(h.second.bytes).c_str());
            }
            std::printf("\n=== Top 会话 ===\n");
            std::vector<nps::ConversationStat> conv = conversations;
            std::sort(conv.begin(), conv.end(),
                      [](const nps::ConversationStat& x, const nps::ConversationStat& y) {
                          return x.bytes > y.bytes;
                      });
            for (size_t i = 0; i < std::min<size_t>(conv.size(), 10); ++i) {
                std::printf("%-45s %-4s %8llu 报文 %12s\n",
                            (conv[i].a + " <-> " + conv[i].b).c_str(), conv[i].proto.c_str(),
                            static_cast<unsigned long long>(conv[i].packets),
                            nps::formatBytes(conv[i].bytes).c_str());
            }
        }

        if (wantPackets > 0) {
            std::printf("\n=== 报文列表（最多 %d 条）===\n", wantPackets);
            std::printf("%-6s %-12s %-24s %-24s %-8s %-6s %s\n", "No.", "Time", "Source",
                        "Destination", "Protocol", "Length", "Info");
            int shown = 0;
            for (const auto* p : matched) {
                if (shown++ >= wantPackets) break;
                std::printf("%-6lld %-12s %-24s %-24s %-8s %-6u %s%s\n",
                            static_cast<long long>(p->index),
                            nps::formatTimestamp(p->ts).c_str(), p->endpointSrc().c_str(),
                            p->endpointDst().c_str(), p->protoLabel().c_str(), p->origlen,
                            p->info.c_str(), p->malformed ? "  [malformed]" : "");
            }
        }

        if (wantStreams) {
            std::printf("\n=== TCP 流 ===\n");
            std::printf("%-4s %-24s %-24s %-12s %8s %10s %6s %6s %8s\n", "ID", "客户端", "服务端",
                        "状态", "报文", "载荷字节", "重传", "乱序", "RTT(ms)");
            for (const auto& s : streams) {
                char rtt[32];
                if (s.handshakeRttMs >= 0)
                    std::snprintf(rtt, sizeof(rtt), "%.2f", s.handshakeRttMs);
                else
                    std::snprintf(rtt, sizeof(rtt), "-");
                std::printf("%-4lld %-24s %-24s %-12s %8llu %10llu %6u %6u %8s\n",
                            static_cast<long long>(s.id),
                            (s.clientIp + ":" + std::to_string(s.clientPort)).c_str(),
                            (s.serverIp + ":" + std::to_string(s.serverPort)).c_str(),
                            s.stateLabel().c_str(),
                            static_cast<unsigned long long>(s.packets),
                            static_cast<unsigned long long>(s.payloadBytes), s.retransmissions,
                            s.outOfOrder, rtt);
            }
        }

        if (wantHttp) {
            std::printf("\n=== HTTP 还原 ===\n");
            for (const auto& s : streams) {
                for (const auto& r : s.httpRequests) {
                    const size_t e = r.find("\r\n");
                    std::printf("[stream %lld] %s\n", static_cast<long long>(s.id),
                                r.substr(0, e).c_str());
                }
                for (const auto& r : s.httpResponses) {
                    const size_t e = r.find("\r\n");
                    std::printf("[stream %lld] %s\n", static_cast<long long>(s.id),
                                r.substr(0, e).c_str());
                }
            }
        }

        if (wantProcs) {
            std::printf("\n=== 进程归因 ===\n%s\n", analyzer.processStatus().c_str());
            for (const auto& s : streams) {
                std::printf("stream %-4lld pid=%-7d %-16s %s\n",
                            static_cast<long long>(s.id), s.pid,
                            s.procName.empty() ? "-" : s.procName.c_str(), s.key().c_str());
            }
        }
    }

    return 0;
}
