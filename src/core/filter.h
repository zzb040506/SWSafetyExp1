// 显示过滤器：支持 and/or/not、括号、协议名、字段比较与 contains/matches
#pragma once

#include <memory>
#include <string>

#include "types.h"

namespace nps {

class DisplayFilter {
public:
    DisplayFilter();
    ~DisplayFilter();
    DisplayFilter(const DisplayFilter&);
    DisplayFilter& operator=(const DisplayFilter&);

    // 编译表达式；空表达式视为全部匹配
    bool compile(const std::string& expr, std::string& error);
    bool matches(const Packet& p) const;
    bool empty() const;
    std::string expression() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

}  // namespace nps
