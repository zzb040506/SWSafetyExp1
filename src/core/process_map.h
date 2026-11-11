// 进程归因：把 TCP 连接映射到本机进程（macOS/Linux/Windows）
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace nps {

struct ProcessConn {
    int32_t pid = -1;
    std::string name;
    std::string localIp;
    uint16_t localPort = 0;
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string state;
};

class ProcessMap {
public:
    // 采集一次系统当前 TCP 连接表
    void refresh();
    // 双向查找；找到返回 true
    bool lookup(const std::string& aIp, uint16_t aPort, const std::string& bIp, uint16_t bPort,
                int32_t& pid, std::string& name) const;

    const std::vector<ProcessConn>& connections() const { return conns_; }
    const std::string& status() const { return status_; }
    bool supported() const { return supported_; }

private:
    static std::string endpointKey(const std::string& ip, uint16_t port);
    std::vector<ProcessConn> conns_;
    std::unordered_map<std::string, std::vector<size_t>> byLocal_;
    std::string status_ = "未刷新";
    bool supported_ = true;
};

}  // namespace nps
