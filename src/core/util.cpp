#include "util.h"

#include <arpa/inet.h>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace nps {

uint16_t readBe16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t readBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t readLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t readLe24(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16);
}

std::string macToString(const uint8_t* p) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3],
                  p[4], p[5]);
    return buf;
}

std::string ipv4ToString(const uint8_t* p) {
    char buf[INET_ADDRSTRLEN];
    if (!::inet_ntop(AF_INET, p, buf, sizeof(buf))) return std::string();
    return buf;
}

std::string ipv6ToString(const uint8_t* p) {
    char buf[INET6_ADDRSTRLEN];
    if (!::inet_ntop(AF_INET6, p, buf, sizeof(buf))) return std::string();
    return buf;
}

std::string toPrintable(const uint8_t* p, size_t len) {
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = p[i];
        if (c == '\r') {
            out.push_back('\\');
            out.push_back('r');
        } else if (c == '\n') {
            out.push_back('\\');
            out.push_back('n');
        } else if (c == '\t') {
            out.push_back('\\');
            out.push_back('t');
        } else if (c >= 0x20 && c < 0x7f) {
            out.push_back(static_cast<char>(c));
        } else if (c >= 0x80) {
            // UTF-8 多字节序列原样保留，便于中文展示
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('.');
        }
    }
    return out;
}

std::vector<std::string> hexDump(const uint8_t* p, size_t len) {
    std::vector<std::string> lines;
    char buf[128];
    for (size_t off = 0; off < len; off += 16) {
        const size_t n = (len - off < 16) ? (len - off) : 16;
        std::string hex;
        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (i < n) {
                std::snprintf(buf, sizeof(buf), "%02x ", p[off + i]);
                hex += buf;
                const uint8_t c = p[off + i];
                ascii.push_back((c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.');
            } else {
                hex += "   ";
                ascii.push_back(' ');
            }
            if (i == 7) hex.push_back(' ');
        }
        std::snprintf(buf, sizeof(buf), "%04zx  ", off);
        lines.push_back(std::string(buf) + hex + " |" + ascii + "|");
    }
    return lines;
}

std::string formatTimestamp(double ts) {
    const double frac = ts - static_cast<double>(static_cast<long long>(ts));
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.6f", frac);
    return std::string(buf).substr(1);  // 形如 ".123456"
}

std::string formatBytes(uint64_t bytes) {
    char buf[64];
    if (bytes < 1024ull) {
        std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
    } else if (bytes < 1024ull * 1024ull) {
        std::snprintf(buf, sizeof(buf), "%.1f KiB", bytes / 1024.0);
    } else if (bytes < 1024ull * 1024ull * 1024ull) {
        std::snprintf(buf, sizeof(buf), "%.1f MiB", bytes / (1024.0 * 1024.0));
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f GiB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
    return buf;
}

std::string flagsToString(uint8_t flags) {
    std::string s;
    if (flags & 0x01) s += "F";
    if (flags & 0x02) s += "S";
    if (flags & 0x04) s += "R";
    if (flags & 0x08) s += "P";
    if (flags & 0x10) s += ".";
    if (flags & 0x20) s += "U";
    if (flags & 0x40) s += "E";
    if (flags & 0x80) s += "C";
    return s;
}

bool parseAddress(const std::string& text, bool& isV6, uint8_t out[16]) {
    std::memset(out, 0, 16);
    if (text.find(':') != std::string::npos) {
        isV6 = true;
        return ::inet_pton(AF_INET6, text.c_str(), out) == 1;
    }
    isV6 = false;
    return ::inet_pton(AF_INET, text.c_str(), out) == 1;
}

bool addressEquals(const std::string& a, const std::string& b) {
    if (a == b) return true;
    bool av6 = false, bv6 = false;
    uint8_t ab[16], bb[16];
    if (!parseAddress(a, av6, ab) || !parseAddress(b, bv6, bb)) return false;
    if (av6 != bv6) return false;
    return std::memcmp(ab, bb, av6 ? 16 : 4) == 0;
}

bool containsNoCase(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    std::string h(haystack), n(needle);
    for (auto& c : h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return h.find(n) != std::string::npos;
}

}  // namespace nps
