// 协议解析器：链路层 -> 网络层 -> 传输层 -> 应用层
#pragma once

#include "types.h"

namespace nps {

class Dissector {
public:
    // 就地填充 Packet 的解析字段与字段树；任何越界都只标记 malformed，不抛异常
    // linkType 取 libpcap 的 DLT_* 值：0=BSD loopback, 1=Ethernet, 101=RAW, 113=Linux SLL
    static void dissect(Packet& p, int linkType = 1);

    // 单独的应用层识别，供流重组后的 HTTP 判定复用
    static bool looksLikeHttp(const uint8_t* p, size_t len);
};

}  // namespace nps
