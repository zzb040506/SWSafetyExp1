#include "filter.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <regex>
#include <sstream>
#include <vector>

#include "util.h"

namespace nps {
namespace {

enum class TokType { Ident, Number, String, Op, LParen, RParen, And, Or, Not, End };

struct Token {
    TokType type = TokType::End;
    std::string text;
    double num = 0.0;
};

bool isIdentChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-';
}

bool tokenize(const std::string& src, std::vector<Token>& out, std::string& error) {
    size_t i = 0;
    while (i < src.size()) {
        const char c = src[i];
        if (std::isspace(static_cast<unsigned char>(c))) {
            ++i;
            continue;
        }
        if (c == '(') {
            out.push_back({TokType::LParen, "("});
            ++i;
            continue;
        }
        if (c == ')') {
            out.push_back({TokType::RParen, ")"});
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            const char quote = c;
            size_t j = i + 1;
            std::string s;
            while (j < src.size() && src[j] != quote) {
                if (src[j] == '\\' && j + 1 < src.size()) {
                    s.push_back(src[j + 1]);
                    j += 2;
                    continue;
                }
                s.push_back(src[j]);
                ++j;
            }
            if (j >= src.size()) {
                error = "字符串缺少闭合引号";
                return false;
            }
            out.push_back({TokType::String, s});
            i = j + 1;
            continue;
        }
        if (c == '&' && i + 1 < src.size() && src[i + 1] == '&') {
            out.push_back({TokType::And, "&&"});
            i += 2;
            continue;
        }
        if (c == '|' && i + 1 < src.size() && src[i + 1] == '|') {
            out.push_back({TokType::Or, "||"});
            i += 2;
            continue;
        }
        if (c == '=' && i + 1 < src.size() && src[i + 1] == '=') {
            out.push_back({TokType::Op, "=="});
            i += 2;
            continue;
        }
        if (c == '!' && i + 1 < src.size() && src[i + 1] == '=') {
            out.push_back({TokType::Op, "!="});
            i += 2;
            continue;
        }
        if (c == '!' ) {
            out.push_back({TokType::Not, "!"});
            ++i;
            continue;
        }
        if (c == '>' || c == '<') {
            std::string op(1, c);
            if (i + 1 < src.size() && src[i + 1] == '=') {
                op.push_back('=');
                i += 2;
            } else {
                ++i;
            }
            out.push_back({TokType::Op, op});
            continue;
        }
        if (c == '=') {  // 容错：单个 = 视为 ==
            out.push_back({TokType::Op, "=="});
            ++i;
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t j = i;
            while (j < src.size() &&
                   (std::isdigit(static_cast<unsigned char>(src[j])) || src[j] == '.')) {
                ++j;
            }
            const std::string numText = src.substr(i, j - i);
            Token t;
            t.type = TokType::Number;
            t.text = numText;
            t.num = std::atof(numText.c_str());
            out.push_back(t);
            i = j;
            continue;
        }
        if (isIdentChar(c)) {
            size_t j = i;
            while (j < src.size() && isIdentChar(src[j])) ++j;
            std::string word = src.substr(i, j - i);
            std::string lower;
            lower.reserve(word.size());
            for (char ch : word) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
            if (lower == "and") {
                out.push_back({TokType::And, word});
            } else if (lower == "or") {
                out.push_back({TokType::Or, word});
            } else if (lower == "not") {
                out.push_back({TokType::Not, word});
            } else if (lower == "contains" || lower == "matches") {
                out.push_back({TokType::Op, lower});
            } else {
                out.push_back({TokType::Ident, word});
            }
            i = j;
            continue;
        }
        error = "无法识别的字符: " + std::string(1, c);
        return false;
    }
    out.push_back({TokType::End, ""});
    return true;
}

struct Ast {
    enum class Kind { And, Or, Not, Atom } kind = Kind::Atom;
    std::shared_ptr<Ast> left;
    std::shared_ptr<Ast> right;
    // Atom 部分
    std::string field;   // 字段名或协议名
    std::string op;      // == != > < >= <= contains matches（空表示布尔协议判断）
    std::string strValue;
    double numValue = 0.0;
    bool numeric = false;
};

std::string lowerCopy(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool isNumericField(const std::string& f) {
    return f == "frame.len" || f == "frame.number" || f == "tcp.port" || f == "udp.port" ||
           f == "tcp.srcport" || f == "tcp.dstport" || f == "udp.srcport" ||
           f == "udp.dstport" || f == "port" || f == "tcp.stream" || f == "ip.len" ||
           f == "proc.pid" || f == "tcp.window" || f == "tcp.flags" || f == "dns.count.answers";
}

class Parser {
public:
    Parser(const std::vector<Token>& toks, std::string& err) : toks_(toks), err_(err) {}

    std::shared_ptr<Ast> parse() {
        auto node = parseOr();
        if (!err_.empty()) return nullptr;
        if (peek().type != TokType::End) {
            err_ = "表达式结尾存在多余内容: " + peek().text;
            return nullptr;
        }
        return node;
    }

private:
    const Token& peek() const { return toks_[pos_]; }
    const Token& next() { return toks_[pos_++]; }

    std::shared_ptr<Ast> parseOr() {
        auto left = parseAnd();
        if (!left) return nullptr;
        while (err_.empty() && peek().type == TokType::Or) {
            next();
            auto right = parseAnd();
            if (!right) return nullptr;
            auto node = std::make_shared<Ast>();
            node->kind = Ast::Kind::Or;
            node->left = left;
            node->right = right;
            left = node;
        }
        return left;
    }

    std::shared_ptr<Ast> parseAnd() {
        auto left = parseUnary();
        while (err_.empty() && peek().type == TokType::And) {
            next();
            auto right = parseUnary();
            if (!right) return nullptr;
            auto node = std::make_shared<Ast>();
            node->kind = Ast::Kind::And;
            node->left = left;
            node->right = right;
            left = node;
        }
        return left;
    }

    std::shared_ptr<Ast> parseUnary() {
        if (peek().type == TokType::Not) {
            next();
            auto child = parseUnary();
            if (!child) return nullptr;
            auto node = std::make_shared<Ast>();
            node->kind = Ast::Kind::Not;
            node->left = child;
            return node;
        }
        return parsePrimary();
    }

    std::shared_ptr<Ast> parsePrimary() {
        if (peek().type == TokType::LParen) {
            next();
            auto node = parseOr();
            if (peek().type != TokType::RParen) {
                err_ = "缺少右括号";
                return nullptr;
            }
            next();
            return node;
        }
        if (peek().type != TokType::Ident) {
            err_ = "此处需要一个字段名或协议名";
            return nullptr;
        }
        auto node = std::make_shared<Ast>();
        node->kind = Ast::Kind::Atom;
        node->field = lowerCopy(next().text);
        if (peek().type == TokType::Op) {
            node->op = lowerCopy(next().text);
            if (peek().type == TokType::Number) {
                node->numeric = true;
                node->numValue = next().num;
            } else if (peek().type == TokType::String || peek().type == TokType::Ident) {
                node->strValue = next().text;
            } else {
                err_ = "比较运算符后缺少取值";
                return nullptr;
            }
        } else if (isNumericField(node->field)) {
            // Wireshark 风格：tcp.port 单独出现等价于 != 0
            node->op = "!=";
            node->numeric = true;
            node->numValue = 0;
        }
        return node;
    }

    const std::vector<Token>& toks_;
    size_t pos_ = 0;
    std::string& err_;
};

std::string packetHttpField(const Packet& p, const std::string& field) {
    // 仅对当前报文载荷做轻量提取
    if (p.payloadLength == 0 || p.payloadOffset >= p.raw.size()) return std::string();
    const size_t n = std::min<size_t>(p.payloadLength, p.raw.size() - p.payloadOffset);
    const std::string text = toPrintable(p.raw.data() + p.payloadOffset, n);
    auto headerValue = [&](const std::string& name) -> std::string {
        const std::string key = name + ":";
        size_t pos = 0;
        while (pos < text.size()) {
            const size_t e = text.find("\\r\\n", pos);
            const std::string line =
                text.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
            if (line.size() >= key.size() && containsNoCase(line.substr(0, key.size()), key)) {
                std::string v = line.substr(key.size());
                while (!v.empty() && v.front() == ' ') v.erase(v.begin());
                return v;
            }
            if (e == std::string::npos) break;
            pos = e + 4;
        }
        return std::string();
    };
    if (field == "http.host") return headerValue("Host");
    if (field == "http.user_agent") return headerValue("User-Agent");
    if (field == "http.request.method") {
        const size_t sp = text.find(' ');
        if (sp == std::string::npos) return std::string();
        return text.substr(0, sp);
    }
    if (field == "http.request.uri") {
        const size_t sp = text.find(' ');
        if (sp == std::string::npos) return std::string();
        const size_t sp2 = text.find(' ', sp + 1);
        if (sp2 == std::string::npos) return std::string();
        return text.substr(sp + 1, sp2 - sp - 1);
    }
    if (field == "http.response.code") {
        if (text.rfind("HTTP/", 0) == 0) {
            const size_t sp = text.find(' ');
            if (sp != std::string::npos) return text.substr(sp + 1, 3);
        }
        return std::string();
    }
    if (field == "http") return p.appProto == "HTTP" ? "1" : "0";
    return std::string();
}

std::string stringField(const Packet& p, const std::string& f) {
    if (f == "ip.src") return p.l3 == L3Proto::IPv4 ? p.srcAddr : std::string();
    if (f == "ip.dst") return p.l3 == L3Proto::IPv4 ? p.dstAddr : std::string();
    if (f == "ip.addr") return p.l3 == L3Proto::IPv4 ? p.srcAddr : std::string();
    if (f == "ipv6.src") return p.l3 == L3Proto::IPv6 ? p.srcAddr : std::string();
    if (f == "ipv6.dst") return p.l3 == L3Proto::IPv6 ? p.dstAddr : std::string();
    if (f == "ipv6.addr") return p.l3 == L3Proto::IPv6 ? p.srcAddr : std::string();
    if (f == "eth.src") return p.ethSrc;
    if (f == "eth.dst") return p.ethDst;
    if (f == "eth") return p.hasEth ? "1" : "0";
    if (f == "frame.protocols") return p.appProto;
    if (f == "proc.name") return p.procName;
    if (f == "tcp" || f == "udp" || f == "http" || f == "dns" || f == "tls" || f == "icmp" ||
        f == "icmpv6" || f == "arp" || f == "ip" || f == "ipv4" || f == "ipv6") {
        (void)f;
        return std::string();
    }
    return packetHttpField(p, f);
}

bool numericField(const Packet& p, const std::string& f, double& out) {
    if (f == "frame.len") { out = p.origlen; return true; }
    if (f == "frame.number") { out = static_cast<double>(p.index); return true; }
    if (f == "ip.len") { out = p.origlen; return true; }
    if (f == "tcp.window") { out = p.window; return true; }
    if (f == "tcp.flags") { out = p.tcpFlags; return true; }
    if (f == "proc.pid") { out = p.pid; return true; }
    if (f == "tcp.stream") { out = static_cast<double>(p.streamId); return true; }
    if (f == "tcp.port") { out = p.srcPort; return true; }
    if (f == "udp.port") { out = p.srcPort; return true; }
    if (f == "port") { out = p.srcPort; return true; }
    if (f == "tcp.srcport") { out = p.srcPort; return true; }
    if (f == "tcp.dstport") { out = p.dstPort; return true; }
    if (f == "udp.srcport") { out = p.srcPort; return true; }
    if (f == "udp.dstport") { out = p.dstPort; return true; }
    return false;
}

bool evalAtom(const Ast& a, const Packet& p) {
    const std::string& f = a.field;

    // 布尔协议判断
    if (a.op.empty()) {
        if (f == "tcp") return p.l4 == L4Proto::Tcp;
        if (f == "udp") return p.l4 == L4Proto::Udp;
        if (f == "icmp") return p.l4 == L4Proto::Icmp;
        if (f == "icmpv6") return p.l4 == L4Proto::Icmpv6;
        if (f == "arp") return p.l3 == L3Proto::Arp;
        if (f == "ip" || f == "ipv4") return p.l3 == L3Proto::IPv4;
        if (f == "ipv6") return p.l3 == L3Proto::IPv6;
        if (f == "eth") return p.hasEth;
        if (f == "http") return p.appProto == "HTTP";
        if (f == "dns") return p.appProto == "DNS";
        if (f == "tls") return p.appProto == "TLS";
        if (f == "tcp.syn") return p.l4 == L4Proto::Tcp && (p.tcpFlags & TcpFlags::Syn) != 0;
        if (f == "tcp.ack") return p.l4 == L4Proto::Tcp && (p.tcpFlags & TcpFlags::Ack) != 0;
        if (f == "tcp.fin") return p.l4 == L4Proto::Tcp && (p.tcpFlags & TcpFlags::Fin) != 0;
        if (f == "tcp.rst") return p.l4 == L4Proto::Tcp && (p.tcpFlags & TcpFlags::Rst) != 0;
        if (f == "tcp.retransmission") return p.retransmission;
        if (f == "tcp.out_of_order") return p.outOfOrder;
        if (f == "tcp.analysis.retransmission") return p.retransmission;
        if (f == "malformed") return p.malformed;
        return false;
    }

    // "port" 系列同时匹配源与目的
    if ((f == "port" || f == "tcp.port" || f == "udp.port") && a.numeric) {
        bool protoOk = true;
        if (f == "tcp.port") protoOk = (p.l4 == L4Proto::Tcp);
        if (f == "udp.port") protoOk = (p.l4 == L4Proto::Udp);
        if (!protoOk) return false;
        const double v = a.numValue;
        if (a.op == "==") return p.srcPort == v || p.dstPort == v;
        if (a.op == "!=") return p.srcPort != v && p.dstPort != v;
        if (a.op == ">") return p.srcPort > v || p.dstPort > v;
        if (a.op == "<") return p.srcPort < v || p.dstPort < v;
        if (a.op == ">=") return p.srcPort >= v || p.dstPort >= v;
        if (a.op == "<=") return p.srcPort <= v || p.dstPort <= v;
        return false;
    }

    if ((f == "ip.addr" || f == "ipv6.addr") && !a.numeric) {
        const bool v6 = (f == "ipv6.addr");
        if ((p.l3 == L3Proto::IPv6) != v6) return false;
        const bool eq = addressEquals(p.srcAddr, a.strValue) || addressEquals(p.dstAddr, a.strValue);
        return (a.op == "!=") ? !eq : eq;
    }

    if (a.numeric) {
        double v = 0;
        if (!numericField(p, f, v)) {
            // 数值型比较但字段为字符串：退化为字符串比较
            const std::string s = stringField(p, f);
            std::ostringstream oss;
            oss << a.numValue;
            if (a.op == "==") return s == oss.str();
            if (a.op == "!=") return s != oss.str();
            return false;
        }
        if (p.l4 == L4Proto::None && (f == "tcp.srcport" || f == "tcp.dstport" || f == "tcp.port"))
            return false;
        if (a.op == "==") return v == a.numValue;
        if (a.op == "!=") return v != a.numValue;
        if (a.op == ">") return v > a.numValue;
        if (a.op == "<") return v < a.numValue;
        if (a.op == ">=") return v >= a.numValue;
        if (a.op == "<=") return v <= a.numValue;
        return false;
    }

    const std::string value = stringField(p, f);
    if (value.empty() && f != "http") return false;
    if (a.op == "contains") return containsNoCase(value, a.strValue);
    if (a.op == "matches") {
        try {
            std::regex re(a.strValue, std::regex::ECMAScript | std::regex::icase);
            return std::regex_search(value, re);
        } catch (const std::regex_error&) {
            return false;
        }
    }
    if (a.op == "==") {
        if (f == "http.host") return containsNoCase(value, a.strValue);
        return value == a.strValue;
    }
    if (a.op == "!=") return !(value == a.strValue);
    if (a.op == ">") return value > a.strValue;
    if (a.op == "<") return value < a.strValue;
    return false;
}

bool eval(const Ast& a, const Packet& p) {
    switch (a.kind) {
        case Ast::Kind::And: return eval(*a.left, p) && eval(*a.right, p);
        case Ast::Kind::Or: return eval(*a.left, p) || eval(*a.right, p);
        case Ast::Kind::Not: return !eval(*a.left, p);
        case Ast::Kind::Atom: return evalAtom(a, p);
    }
    return false;
}

}  // namespace

struct DisplayFilter::Impl {
    std::shared_ptr<Ast> root;
    std::string expression;
    bool compiled = false;
};

DisplayFilter::DisplayFilter() : impl_(std::make_shared<Impl>()) {}
DisplayFilter::~DisplayFilter() = default;
DisplayFilter::DisplayFilter(const DisplayFilter&) = default;
DisplayFilter& DisplayFilter::operator=(const DisplayFilter&) = default;

bool DisplayFilter::compile(const std::string& expr, std::string& error) {
    impl_->expression = expr;
    impl_->root.reset();
    impl_->compiled = false;
    if (expr.find_first_not_of(" \t\r\n") == std::string::npos) {
        impl_->compiled = true;
        return true;
    }
    std::vector<Token> toks;
    if (!tokenize(expr, toks, error)) return false;
    Parser parser(toks, error);
    auto ast = parser.parse();
    if (!ast) {
        if (error.empty()) error = "表达式语法错误";
        return false;
    }
    impl_->root = ast;
    impl_->compiled = true;
    return true;
}

bool DisplayFilter::matches(const Packet& p) const {
    if (!impl_->compiled) return true;
    if (!impl_->root) return true;
    return eval(*impl_->root, p);
}

bool DisplayFilter::empty() const {
    return impl_->expression.find_first_not_of(" \t\r\n") == std::string::npos;
}

std::string DisplayFilter::expression() const { return impl_->expression; }

}  // namespace nps
