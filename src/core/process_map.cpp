#include "process_map.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <dirent.h>
#include <unistd.h>
#endif

#include "util.h"

namespace nps {
namespace {

std::string trimCopy(const std::string& s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

bool splitEndpoint(const std::string& text, std::string& ip, uint16_t& port) {
    const std::string t = trimCopy(text);
    if (t.empty()) return false;
    if (t[0] == '[') {
        const size_t close = t.find(']');
        if (close == std::string::npos) return false;
        ip = t.substr(1, close - 1);
        const size_t colon = t.find(':', close);
        if (colon == std::string::npos) return false;
        port = static_cast<uint16_t>(std::atoi(t.c_str() + colon + 1));
        return true;
    }
    const size_t colon = t.rfind(':');
    if (colon == std::string::npos) return false;
    ip = t.substr(0, colon);
    port = static_cast<uint16_t>(std::atoi(t.c_str() + colon + 1));
    return true;
}

#if !defined(_WIN32)

// 把 /proc/net/tcp 中的小端十六进制地址转换为可读文本
std::string procHexToIp(const std::string& hex, bool v6) {
    if (!v6) {
        if (hex.size() != 8) return std::string();
        uint8_t bytes[4];
        for (int i = 0; i < 4; ++i) {
            const std::string part = hex.substr(i * 2, 2);
            bytes[3 - i] = static_cast<uint8_t>(std::strtoul(part.c_str(), nullptr, 16));
        }
        return ipv4ToString(bytes);
    }
    if (hex.size() != 32) return std::string();
    uint8_t bytes[16];
    for (int word = 0; word < 4; ++word) {
        for (int b = 0; b < 4; ++b) {
            const std::string part = hex.substr(word * 8 + b * 2, 2);
            bytes[word * 4 + (3 - b)] =
                static_cast<uint8_t>(std::strtoul(part.c_str(), nullptr, 16));
        }
    }
    return ipv6ToString(bytes);
}

void parseProcNetTcp(const std::string& path, bool v6, std::vector<ProcessConn>& out) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    std::getline(in, line);  // 表头
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, st, txrx, tr, retr, uid, timeout, inode;
        if (!(iss >> sl >> local >> remote >> st >> txrx >> tr >> retr >> uid >> timeout >> inode))
            continue;
        const size_t c1 = local.find(':');
        const size_t c2 = remote.find(':');
        if (c1 == std::string::npos || c2 == std::string::npos) continue;
        ProcessConn c;
        c.localIp = procHexToIp(local.substr(0, c1), v6);
        c.remoteIp = procHexToIp(remote.substr(0, c2), v6);
        c.localPort = static_cast<uint16_t>(std::strtoul(local.substr(c1 + 1).c_str(), nullptr, 16));
        c.remotePort =
            static_cast<uint16_t>(std::strtoul(remote.substr(c2 + 1).c_str(), nullptr, 16));
        c.state = st;
        // 以 inode 作为连接标识，稍后回填 PID
        c.name = inode;
        if (c.localPort == 0) continue;
        out.push_back(std::move(c));
    }
}

void mapInodesToPids(std::vector<ProcessConn>& conns) {
    if (conns.empty()) return;
    std::vector<std::pair<std::string, int32_t>> inodePid;
    DIR* proc = opendir("/proc");
    if (!proc) return;
    while (dirent* de = readdir(proc)) {
        const std::string pidStr = de->d_name;
        if (pidStr.empty() ||
            pidStr.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }
        const std::string fdDir = "/proc/" + pidStr + "/fd";
        DIR* fds = opendir(fdDir.c_str());
        if (!fds) continue;
        while (dirent* fe = readdir(fds)) {
            if (fe->d_name[0] == '.') continue;
            const std::string link = fdDir + "/" + fe->d_name;
            char buf[256];
            const ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
            if (n <= 0) continue;
            buf[n] = '\0';
            const std::string target(buf);
            if (target.rfind("socket:[", 0) == 0) {
                const size_t end = target.find(']');
                if (end != std::string::npos) {
                    inodePid.emplace_back(target.substr(8, end - 8),
                                          static_cast<int32_t>(std::atoi(pidStr.c_str())));
                }
            }
        }
        closedir(fds);
    }
    closedir(proc);

    for (auto& c : conns) {
        for (const auto& pr : inodePid) {
            if (pr.first == c.name) {
                c.pid = pr.second;
                char commPath[128];
                std::snprintf(commPath, sizeof(commPath), "/proc/%d/comm", c.pid);
                std::ifstream comm(commPath);
                std::string name;
                if (std::getline(comm, name)) c.name = trimCopy(name);
                break;
            }
        }
    }
}

#endif  // !_WIN32

}  // namespace

void ProcessMap::refresh() {
    conns_.clear();
    byLocal_.clear();
#if defined(_WIN32)
    supported_ = true;
    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc == ERROR_INSUFFICIENT_BUFFER && size > 0) {
        std::vector<uint8_t> buf(size);
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
        if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) ==
            NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const MIB_TCPROW_OWNER_PID& row = table->table[i];
                ProcessConn c;
                c.pid = static_cast<int32_t>(row.dwOwningPid);
                uint8_t la[4], ra[4];
                const uint32_t l = row.dwLocalAddr;
                const uint32_t r = row.dwRemoteAddr;
                la[0] = static_cast<uint8_t>(l & 0xff);
                la[1] = static_cast<uint8_t>((l >> 8) & 0xff);
                la[2] = static_cast<uint8_t>((l >> 16) & 0xff);
                la[3] = static_cast<uint8_t>((l >> 24) & 0xff);
                ra[0] = static_cast<uint8_t>(r & 0xff);
                ra[1] = static_cast<uint8_t>((r >> 8) & 0xff);
                ra[2] = static_cast<uint8_t>((r >> 16) & 0xff);
                ra[3] = static_cast<uint8_t>((r >> 24) & 0xff);
                c.localIp = ipv4ToString(la);
                c.remoteIp = ipv4ToString(ra);
                c.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                c.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                switch (row.dwState) {
                    case MIB_TCP_STATE_ESTAB: c.state = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_LISTEN: c.state = "LISTEN"; break;
                    case MIB_TCP_STATE_TIME_WAIT: c.state = "TIME_WAIT"; break;
                    default: c.state = "OTHER"; break;
                }
                char exe[MAX_PATH] = {0};
                DWORD exeSize = sizeof(exe);
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.dwOwningPid);
                if (h) {
                    if (QueryFullProcessImageNameA(h, 0, exe, &exeSize)) {
                        std::string path(exe);
                        const size_t slash = path.find_last_of("\\/");
                        c.name = (slash == std::string::npos) ? path : path.substr(slash + 1);
                    }
                    CloseHandle(h);
                }
                conns_.push_back(std::move(c));
            }
        }
    }
    status_ = "Windows IP Helper API: " + std::to_string(conns_.size()) + " 条连接";
#elif defined(__APPLE__)
    supported_ = true;
    FILE* f = popen("lsof -nP -iTCP 2>/dev/null", "r");
    if (!f) {
        status_ = "无法执行 lsof";
        return;
    }
    int32_t curPid = -1;
    std::string curName;
    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        const std::string text = trimCopy(line);
        if (text.empty()) continue;
        switch (text[0]) {
            case 'p':
                curPid = static_cast<int32_t>(std::atoi(text.c_str() + 1));
                break;
            case 'c':
                curName = text.substr(1);
                break;
            case 'n': {
                const std::string names = text.substr(1);
                const size_t arrow = names.find("->");
                if (arrow == std::string::npos) break;
                ProcessConn c;
                c.pid = curPid;
                c.name = curName;
                if (!splitEndpoint(names.substr(0, arrow), c.localIp, c.localPort)) break;
                if (!splitEndpoint(names.substr(arrow + 2), c.remoteIp, c.remotePort)) break;
                c.state = "ESTABLISHED";
                conns_.push_back(std::move(c));
                break;
            }
            default:
                break;
        }
    }
    pclose(f);
    status_ = "lsof: " + std::to_string(conns_.size()) + " 条连接";
#else
    std::vector<ProcessConn> v4, v6;
    parseProcNetTcp("/proc/net/tcp", false, v4);
    parseProcNetTcp("/proc/net/tcp6", true, v6);
    conns_ = std::move(v4);
    conns_.insert(conns_.end(), v6.begin(), v6.end());
    mapInodesToPids(conns_);
    status_ = "/proc/net/tcp: " + std::to_string(conns_.size()) + " 条连接";
#endif
    if (conns_.empty()) {
        status_ = "未获取到 TCP 连接（可能需要相应权限）";
    }
    for (size_t i = 0; i < conns_.size(); ++i) {
        byLocal_[endpointKey(conns_[i].localIp, conns_[i].localPort)].push_back(i);
    }
}

std::string ProcessMap::endpointKey(const std::string& ip, uint16_t port) {
    return ip + "#" + std::to_string(port);
}

bool ProcessMap::lookup(const std::string& aIp, uint16_t aPort, const std::string& bIp,
                        uint16_t bPort, int32_t& pid, std::string& name) const {
    auto tryEndpoint = [&](const std::string& ip, uint16_t port, const std::string& rip,
                           uint16_t rport) -> bool {
        auto it = byLocal_.find(endpointKey(ip, port));
        if (it == byLocal_.end()) {
            // 地址字符串可能有 IPv4 映射差异，退化为端口扫描
            for (const auto& kv : byLocal_) {
                const size_t hash = kv.first.rfind('#');
                if (hash == std::string::npos) continue;
                if (static_cast<uint16_t>(std::atoi(kv.first.c_str() + hash + 1)) != port) continue;
                for (size_t idx : kv.second) {
                    const ProcessConn& c = conns_[idx];
                    if (c.remotePort == rport) {
                        pid = c.pid;
                        name = c.name;
                        return true;
                    }
                }
            }
            return false;
        }
        for (size_t idx : it->second) {
            const ProcessConn& c = conns_[idx];
            if (c.remotePort == 0 || c.remotePort == rport) {
                pid = c.pid;
                name = c.name;
                return true;
            }
        }
        return false;
    };

    if (tryEndpoint(aIp, aPort, bIp, bPort)) return true;
    if (tryEndpoint(bIp, bPort, aIp, aPort)) return true;
    return false;
}

}  // namespace nps
