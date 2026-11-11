// 字节读取、地址格式化、时间格式化等工具函数
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace nps {

uint16_t readBe16(const uint8_t* p);
uint32_t readBe32(const uint8_t* p);
uint16_t readLe16(const uint8_t* p);
uint32_t readLe24(const uint8_t* p);

std::string macToString(const uint8_t* p);
std::string ipv4ToString(const uint8_t* p);
std::string ipv6ToString(const uint8_t* p);

// 把二进制载荷转成可读文本：可打印字符保留，控制字符转 '.'
std::string toPrintable(const uint8_t* p, size_t len);

// 十六进制 dump，返回 "0000  48 54 54 50 ...  |HTTP..." 形式的行
std::vector<std::string> hexDump(const uint8_t* p, size_t len);

std::string formatTimestamp(double ts);
std::string formatBytes(uint64_t bytes);
std::string flagsToString(uint8_t flags);

// 解析 "1.2.3.4" / "::1" 形式地址，失败返回空
bool parseAddress(const std::string& text, bool& isV6, uint8_t out[16]);
bool addressEquals(const std::string& a, const std::string& b);

// 简单通配/包含判断（不区分大小写）
bool containsNoCase(const std::string& haystack, const std::string& needle);

}  // namespace nps
