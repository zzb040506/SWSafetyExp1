#include "app.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "core/util.h"
#include "imgui_stdlib.h"

namespace {

ImU32 colorForPacket(const nps::Packet& p) {
    if (p.malformed) return IM_COL32(72, 24, 24, 255);
    if (p.retransmission) return IM_COL32(70, 60, 20, 255);
    if (p.outOfOrder) return IM_COL32(66, 44, 22, 255);
    if (p.appProto == "HTTP") return IM_COL32(20, 46, 62, 255);
    if (p.appProto == "DNS") return IM_COL32(22, 52, 34, 255);
    if (p.appProto == "TLS") return IM_COL32(40, 34, 62, 255);
    return 0;
}

std::string fieldLabel(const nps::FieldNode& node) {
    std::string text = node.name;
    if (!node.value.empty()) {
        if (!text.empty()) text += ": ";
        text += node.value;
    }
    return text;
}

}  // namespace

SnifferApp::SnifferApp(const AppOptions& options) : options_(options) {
    std::string err;
    filter_.compile("", err);
    filterText_ = options_.displayFilter;
    bpfText_ = options_.bpf;
    sideTab_ = options_.tab;

    std::string devErr;
    devices_ = nps::CaptureEngine::listDevices(devErr);
    if (!options_.device.empty()) {
        for (size_t i = 0; i < devices_.size(); ++i) {
            if (devices_[i].name == options_.device) deviceIndex_ = static_cast<int>(i);
        }
    }

    if (!options_.openPcap.empty()) {
        std::string openErr;
        openFile(options_.openPcap, openErr);
        if (!openErr.empty()) statusMessage_ = openErr;
    }
    if (!filterText_.empty()) applyDisplayFilter(filterText_);

    // 演示录制：pcap 相对同目录的其它样例文件
    if (!options_.recordDir.empty() && !options_.openPcap.empty()) {
        const size_t slash = options_.openPcap.find_last_of('/');
        demoDir_ = (slash == std::string::npos) ? std::string()
                                                : options_.openPcap.substr(0, slash + 1);
    }

    if (!options_.device.empty() && options_.captureSeconds > 0) {
        startLive(options_.device);
    }
    if (options_.selectRow > 0) selectRow(options_.selectRow);
}

SnifferApp::~SnifferApp() { stopLive(); }

bool SnifferApp::packetAt(int row, nps::Packet& out) const {
    if (row < 0 || row >= static_cast<int>(rows_.size())) return false;
    auto lock = analyzer_.lock();
    const auto& packets = analyzer_.packetsUnlocked();
    const int64_t idx = rows_[static_cast<size_t>(row)];
    if (idx < 0 || idx >= static_cast<int64_t>(packets.size())) return false;
    out = packets[static_cast<size_t>(idx)];
    return true;
}

int SnifferApp::findRow(const std::function<bool(const nps::Packet&)>& pred) const {
    for (int i = 0; i < static_cast<int>(rows_.size()); ++i) {
        nps::Packet p;
        if (packetAt(i, p) && pred(p)) return i;
    }
    return -1;
}

void SnifferApp::updateDetail(int row) {    nps::Packet packet;
    if (!packetAt(row, packet)) {
        detailValid_ = false;
        hexData_.clear();
        return;
    }
    detailPacket_ = std::move(packet);
    detailValid_ = true;
    hexData_ = detailPacket_.raw;
    highlightOffset_ = -1;
    highlightLength_ = 0;
    scrollDetail_ = true;
}

void SnifferApp::selectRow(int row) {
    if (rows_.empty()) return;
    if (row < 0) row = 0;
    if (row >= static_cast<int>(rows_.size())) row = static_cast<int>(rows_.size()) - 1;
    selectedRow_ = row;
    updateDetail(row);
}

void SnifferApp::refreshRows() {
    size_t total = 0;
    {
        auto lock = analyzer_.lock();
        total = analyzer_.packetsUnlocked().size();
        if (firstTs_ < 0 && !analyzer_.packetsUnlocked().empty())
            firstTs_ = analyzer_.packetsUnlocked().front().ts;
    }
    if (scanned_ >= total) return;

    std::vector<int64_t> appended;
    {
        auto lock = analyzer_.lock();
        const auto& packets = analyzer_.packetsUnlocked();
        const size_t limit = std::min(total, packets.size());
        for (size_t i = scanned_; i < limit; ++i) {
            if (filter_.matches(packets[i])) appended.push_back(static_cast<int64_t>(i));
        }
    }
    scanned_ = total;
    rows_.insert(rows_.end(), appended.begin(), appended.end());
}

void SnifferApp::applyDisplayFilter(const std::string& expression) {
    nps::DisplayFilter next;
    std::string err;
    if (!next.compile(expression, err)) {
        filterError_ = err;
        return;
    }
    filterError_.clear();
    filter_ = next;
    filterText_ = expression;
    rows_.clear();
    scanned_ = 0;
    selectedRow_ = -1;
    detailValid_ = false;
    hexData_.clear();
    refreshRows();
    if (!rows_.empty()) selectRow(0);
}

bool SnifferApp::openFile(const std::string& path, std::string& error) {
    stopLive();
    analyzer_.reset();
    rows_.clear();
    scanned_ = 0;
    firstTs_ = -1.0;
    selectedRow_ = -1;
    detailValid_ = false;
    hexData_.clear();

    if (!capture_.openOffline(path, error)) return false;
    if (!bpfText_.empty()) {
        std::string bpfErr;
        capture_.setBpfFilter(bpfText_, bpfErr);
    }
    analyzer_.setLinkType(capture_.linkType());
    analyzer_.start();
    capture_.readOfflineAll([this](nps::RawPacket&& p) { analyzer_.enqueue(std::move(p)); });
    analyzer_.waitIdle();
    analyzer_.stop();
    refreshRows();
    currentFile_ = path;
    if (!rows_.empty()) selectRow(0);
    statusMessage_ = "已载入 " + path + "（" + std::to_string(rows_.size()) + " 条可见报文）";
    return true;
}

void SnifferApp::startLive(const std::string& device) {
    stopLive();
    analyzer_.reset();
    rows_.clear();
    scanned_ = 0;
    firstTs_ = -1.0;
    selectedRow_ = -1;
    detailValid_ = false;
    hexData_.clear();

    std::string err;
    if (!capture_.openLive(device, err)) {
        statusMessage_ = err;
        return;
    }
    if (!bpfText_.empty()) {
        std::string bpfErr;
        if (!capture_.setBpfFilter(bpfText_, bpfErr)) {
            statusMessage_ = bpfErr;
            capture_.stop();
            return;
        }
    }
    analyzer_.setLinkType(capture_.linkType());
    analyzer_.setProcessAttribution(attribution_);
    analyzer_.start();
    capture_.setSink([this](nps::RawPacket&& p) { analyzer_.enqueue(std::move(p)); });
    if (!capture_.startLive(err)) {
        statusMessage_ = err;
        return;
    }
    capturing_ = true;
    statusMessage_ = "开始捕获：" + device;
}

void SnifferApp::stopLive() {
    if (!capturing_) return;
    capture_.stop();
    analyzer_.waitIdle();
    analyzer_.stop();
    capturing_ = false;
    refreshRows();
    statusMessage_ = "已停止捕获";
}

void SnifferApp::clearAll() {
    stopLive();
    analyzer_.reset();
    rows_.clear();
    scanned_ = 0;
    firstTs_ = -1.0;
    selectedRow_ = -1;
    detailValid_ = false;
    hexData_.clear();
    streamCache_.clear();
    hierarchyCache_.clear();
    conversationCache_.clear();
    processCache_.clear();
    currentFile_.clear();
}

bool SnifferApp::exportPcap(const std::string& path, std::string& error) {
    auto lock = analyzer_.lock();
    const auto& packets = analyzer_.packetsUnlocked();
    if (packets.empty()) {
        error = "当前没有可保存的报文";
        return false;
    }
    pcap_t* dead = pcap_open_dead(analyzer_.linkType(), 262144);
    if (!dead) {
        error = "pcap_open_dead 失败";
        return false;
    }
    pcap_dumper_t* dumper = pcap_dump_open(dead, path.c_str());
    if (!dumper) {
        error = pcap_geterr(dead);
        pcap_close(dead);
        return false;
    }
    for (const auto& p : packets) {
        struct pcap_pkthdr hdr;
        hdr.ts.tv_sec = static_cast<long>(p.ts);
        hdr.ts.tv_usec = static_cast<long>((p.ts - static_cast<double>(hdr.ts.tv_sec)) * 1e6);
        hdr.caplen = p.caplen;
        hdr.len = p.origlen;
        pcap_dump(reinterpret_cast<u_char*>(dumper), &hdr, p.raw.data());
    }
    pcap_dump_close(dumper);
    pcap_close(dead);
    return true;
}

void SnifferApp::drawTopBar() {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 5));
    ImGui::TextUnformatted("NPS Sniffer");
    ImGui::SameLine();
    ImGui::TextDisabled("网络嗅探与协议分析  |  占智博 202618018629010");
    ImGui::SameLine(0, 24);
    if (ImGui::Button("打开 pcap")) {
        dialogMode_ = 1;
        std::snprintf(pathBuf_, sizeof(pathBuf_), "%s",
                      currentFile_.empty() ? "tests/http_basic.pcap" : currentFile_.c_str());
        ImGui::OpenPopup("文件路径");
    }
    ImGui::SameLine();
    if (ImGui::Button("保存 pcap")) {
        dialogMode_ = 2;
        std::snprintf(pathBuf_, sizeof(pathBuf_), "capture.pcap");
        ImGui::OpenPopup("文件路径");
    }
    ImGui::SameLine();
    if (ImGui::Button("清空")) clearAll();

    ImGui::SameLine(0, 24);
    ImGui::TextUnformatted("网卡");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(240);
    std::string preview = devices_.empty()
                              ? std::string("（无可用网卡）")
                              : devices_[static_cast<size_t>(deviceIndex_)].name;
    if (ImGui::BeginCombo("##device", preview.c_str())) {
        for (size_t i = 0; i < devices_.size(); ++i) {
            const bool selected = static_cast<int>(i) == deviceIndex_;
            std::string label = devices_[i].name;
            if (!devices_[i].description.empty()) label += "  (" + devices_[i].description + ")";
            if (devices_[i].loopback) label += " [loopback]";
            if (ImGui::Selectable(label.c_str(), selected)) deviceIndex_ = static_cast<int>(i);
            if (selected) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button(capturing_ ? "停止" : "开始捕获")) {
        if (capturing_) {
            stopLive();
        } else if (!devices_.empty()) {
            startLive(devices_[static_cast<size_t>(deviceIndex_)].name);
        }
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("进程归因", &attribution_)) {
        analyzer_.setProcessAttribution(attribution_);
    }
    ImGui::PopStyleVar();
}

void SnifferApp::drawFilterBar() {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 4));
    ImGui::TextUnformatted("BPF");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260);
    ImGui::InputText("##bpf", &bpfText_);
    ImGui::SameLine();
    ImGui::TextDisabled("内核过滤，重开抓包生效");
    ImGui::SameLine(0, 20);
    ImGui::TextUnformatted("显示过滤");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(360);
    const bool enter = ImGui::InputText("##display", &filterText_,
                                        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("应用") || enter) applyDisplayFilter(filterText_);
    ImGui::SameLine();
    if (!filterError_.empty()) {
        ImGui::TextColored(ImVec4(0.94f, 0.42f, 0.42f, 1.0f), "表达式错误：%s",
                           filterError_.c_str());
    } else {
        ImGui::TextDisabled("匹配 %d 条", static_cast<int>(rows_.size()));
    }
    ImGui::PopStyleVar();
}

void SnifferApp::drawPacketTable(const ImVec2& size) {
    // 表格自身作为滚动容器（ScrollY 需要显式外框尺寸），不再嵌套子窗口
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                  ImGuiTableFlags_BordersOuter | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable;
    const float S = ImGui::GetFontSize() / 16.0f;
    if (ImGui::BeginTable("##pkt", 7, flags, size)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 62 * S);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 96 * S);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthStretch, 1.6f);
        ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthStretch, 1.6f);
        ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 84 * S);
        ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 62 * S);
        ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch, 3.2f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(rows_.size()));
        while (clipper.Step()) {
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                nps::Packet pkt;
                if (!packetAt(r, pkt)) continue;
                ImGui::TableNextRow();
                const ImU32 rowColor = colorForPacket(pkt);
                if (rowColor != 0) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, rowColor);

                ImGui::TableSetColumnIndex(0);
                char indexText[32];
                std::snprintf(indexText, sizeof(indexText), "%lld",
                              static_cast<long long>(pkt.index));
                if (ImGui::Selectable(indexText, selectedRow_ == r,
                                      ImGuiSelectableFlags_SpanAllColumns |
                                          ImGuiSelectableFlags_AllowOverlap,
                                      ImVec2(0, 0))) {
                    selectRow(r);
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) selectRow(r);

                ImGui::TableSetColumnIndex(1);
                char timeText[32];
                const double rel = (firstTs_ >= 0) ? (pkt.ts - firstTs_) : pkt.ts;
                std::snprintf(timeText, sizeof(timeText), "%.6f", rel);
                ImGui::TextUnformatted(timeText);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(pkt.endpointSrc().c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(pkt.endpointDst().c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(pkt.protoLabel().c_str());
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%u", pkt.origlen);
                ImGui::TableSetColumnIndex(6);
                ImGui::TextUnformatted(pkt.info.c_str());
            }
        }
        ImGui::EndTable();
    }
}

void SnifferApp::drawFieldNode(const nps::FieldNode& node, int depth) {
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_SpanAvailWidth |
                               ImGuiTreeNodeFlags_DefaultOpen;
    if (node.children.empty()) flags |= ImGuiTreeNodeFlags_Leaf;
    const std::string label = fieldLabel(node);
    ImGui::PushID(&node);
    const bool open = ImGui::TreeNodeEx("##field", flags, "%s", label.c_str());
    if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen()) {
        highlightOffset_ = static_cast<int>(node.offset);
        highlightLength_ = static_cast<int>(node.length);
        scrollToHighlight_ = true;
    }
    if (open) {
        for (const auto& child : node.children) drawFieldNode(child, depth + 1);
        ImGui::TreePop();
    }
    ImGui::PopID();
}

void SnifferApp::drawHexView(const ImVec2& size) {
    ImGui::BeginChild("##hex", size, ImGuiChildFlags_Border, ImGuiWindowFlags_HorizontalScrollbar);
    if (hexData_.empty()) {
        ImGui::TextDisabled("（无数据）");
        ImGui::EndChild();
        return;
    }
    ImGui::PushFont(monoFont_);
    const float charW = ImGui::CalcTextSize("0").x;
    const float lineH = ImGui::GetTextLineHeight() + 1.0f;
    const int bytesPerLine = 16;
    const int lines = static_cast<int>((hexData_.size() + bytesPerLine - 1) / bytesPerLine);
    const float offsetW = charW * 6.0f;
    const float asciiX = offsetW + charW * (bytesPerLine * 3.0f + 2.0f);

    const ImVec2 origin = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(asciiX + charW * (bytesPerLine + 4.0f) + 24.0f, lines * lineH));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(origin, ImVec2(origin.x + size.x, origin.y + size.y), true);

    if (scrollToHighlight_ && highlightOffset_ >= 0) {
        const int line = highlightOffset_ / bytesPerLine;
        ImGui::SetScrollY(std::max(0.0f, line * lineH - size.y * 0.3f));
        scrollToHighlight_ = false;
    }
    const float scrollY = ImGui::GetScrollY();
    const int firstLine = std::max(0, static_cast<int>(scrollY / lineH) - 1);
    const int lastLine = std::min(lines - 1, static_cast<int>((scrollY + size.y) / lineH) + 1);

    for (int line = firstLine; line <= lastLine; ++line) {
        const int base = line * bytesPerLine;
        const float y = origin.y + line * lineH - scrollY;
        char offsetText[16];
        std::snprintf(offsetText, sizeof(offsetText), "%04x", base);
        dl->AddText(ImVec2(origin.x + 4, y), IM_COL32(120, 132, 146, 255), offsetText);

        for (int i = 0; i < bytesPerLine; ++i) {
            const int pos = base + i;
            if (pos >= static_cast<int>(hexData_.size())) break;
            const float x = origin.x + offsetW + charW * (i * 3.0f) + (i >= 8 ? charW : 0.0f);
            const bool highlighted =
                highlightOffset_ >= 0 && pos >= highlightOffset_ &&
                pos < highlightOffset_ + std::max(1, highlightLength_);
            if (highlighted) dl->AddRectFilled(ImVec2(x - 1, y), ImVec2(x + charW * 2, y + lineH),
                                               IM_COL32(255, 196, 80, 200));
            char byteText[4];
            std::snprintf(byteText, sizeof(byteText), "%02x", hexData_[static_cast<size_t>(pos)]);
            dl->AddText(ImVec2(x, y),
                        highlighted ? IM_COL32(20, 20, 20, 255) : IM_COL32(220, 224, 230, 255),
                        byteText);
        }
        for (int i = 0; i < bytesPerLine; ++i) {
            const int pos = base + i;
            if (pos >= static_cast<int>(hexData_.size())) break;
            const float x = origin.x + asciiX + charW * i;
            const bool highlighted =
                highlightOffset_ >= 0 && pos >= highlightOffset_ &&
                pos < highlightOffset_ + std::max(1, highlightLength_);
            if (highlighted) dl->AddRectFilled(ImVec2(x, y), ImVec2(x + charW, y + lineH),
                                               IM_COL32(255, 196, 80, 200));
            const unsigned char c = hexData_[static_cast<size_t>(pos)];
            char text[2] = {static_cast<char>((c >= 0x20 && c < 0x7f) ? c : '.'), '\0'};
            dl->AddText(ImVec2(x, y),
                        highlighted ? IM_COL32(20, 20, 20, 255) : IM_COL32(180, 190, 200, 255),
                        text);
        }
    }
    dl->PopClipRect();
    ImGui::PopFont();
    ImGui::EndChild();
}

void SnifferApp::drawDetailPane(const ImVec2& size) {
    (void)size;
    ImGui::PushFont(monoFont_);
    if (detailValid_) {
        drawFieldNode(detailPacket_.root, 0);
        // 应用层节点在树的最下方，选中报文后自动滚到底部，便于直接看到 HTTP/DNS 字段
        if (scrollDetail_ && ImGui::GetScrollMaxY() > 0.0f) {
            ImGui::SetScrollHereY(1.0f);
            scrollDetail_ = false;
        }
    } else {
        ImGui::TextDisabled("（选中报文后显示协议字段）");
    }
    ImGui::PopFont();
}

void SnifferApp::drawStreamTable() {
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX |
                                  ImGuiTableFlags_Resizable;
    const float S = ImGui::GetFontSize() / 16.0f;
    if (ImGui::BeginTable("##streams", 10, flags, ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupScrollFreeze(1, 1);
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 48 * S);
        ImGui::TableSetupColumn("应用", ImGuiTableColumnFlags_WidthFixed, 60 * S);
        ImGui::TableSetupColumn("客户端", ImGuiTableColumnFlags_WidthFixed, 150 * S);
        ImGui::TableSetupColumn("服务端", ImGuiTableColumnFlags_WidthFixed, 150 * S);
        ImGui::TableSetupColumn("状态", ImGuiTableColumnFlags_WidthFixed, 96 * S);
        ImGui::TableSetupColumn("报文", ImGuiTableColumnFlags_WidthFixed, 56 * S);
        ImGui::TableSetupColumn("重传", ImGuiTableColumnFlags_WidthFixed, 48 * S);
        ImGui::TableSetupColumn("乱序", ImGuiTableColumnFlags_WidthFixed, 48 * S);
        ImGui::TableSetupColumn("RTT", ImGuiTableColumnFlags_WidthFixed, 62 * S);
        ImGui::TableSetupColumn("进程/主机", ImGuiTableColumnFlags_WidthFixed, 150 * S);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(streamCache_.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const nps::TcpStream& s = streamCache_[static_cast<size_t>(i)];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char label[32];
                std::snprintf(label, sizeof(label), "##stream%d", i);
                if (ImGui::Selectable(label, selectedStream_ == i,
                                      ImGuiSelectableFlags_SpanAllColumns |
                                          ImGuiSelectableFlags_AllowOverlap,
                                      ImVec2(0, 0))) {
                    selectedStream_ = i;
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    applyDisplayFilter("tcp.stream == " + std::to_string(s.id));
                }
                ImGui::SameLine(0, 0);
                ImGui::Text("%lld", static_cast<long long>(s.id));
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(s.appProtocol().c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s:%u", s.clientIp.c_str(), s.clientPort);
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s:%u", s.serverIp.c_str(), s.serverPort);
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(s.stateLabel().c_str());
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%llu", static_cast<unsigned long long>(s.packets));
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%u", s.retransmissions);
                ImGui::TableSetColumnIndex(7);
                ImGui::Text("%u", s.outOfOrder);
                ImGui::TableSetColumnIndex(8);
                if (s.handshakeRttMs >= 0) ImGui::Text("%.2f", s.handshakeRttMs);
                else ImGui::TextUnformatted("-");
                ImGui::TableSetColumnIndex(9);
                if (s.pid >= 0) {
                    ImGui::Text("%s (%d)%s", s.procName.c_str(), s.pid,
                                s.httpHost.empty() ? "" : ("  " + s.httpHost).c_str());
                } else {
                    ImGui::TextDisabled("%s", s.httpHost.empty() ? "-" : s.httpHost.c_str());
                }
            }
        }
        ImGui::EndTable();
    }
    ImGui::TextDisabled("共 %d 条 TCP 流（双击某行按 tcp.stream 过滤）",
                        static_cast<int>(streamCache_.size()));
}

void SnifferApp::drawHierarchy() {
    const float S = ImGui::GetFontSize() / 16.0f;
    if (ImGui::BeginTable("##hier", 3,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_ScrollY,
                          ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("协议层", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("报文", ImGuiTableColumnFlags_WidthFixed, 70 * S);
        ImGui::TableSetupColumn("字节", ImGuiTableColumnFlags_WidthFixed, 84 * S);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const auto& kv : hierarchyCache_) {
            int depth = 0;
            for (char c : kv.first)
                if (c == '|') ++depth;
            std::string leaf = kv.first;
            const size_t bar = leaf.rfind('|');
            if (bar != std::string::npos) leaf = leaf.substr(bar + 1);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Dummy(ImVec2(static_cast<float>(depth) * 14.0f * S, 1.0f));
            ImGui::SameLine(0, 0);
            ImGui::TextUnformatted(leaf.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%llu", static_cast<unsigned long long>(kv.second.packets));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(nps::formatBytes(kv.second.bytes).c_str());
        }
        ImGui::EndTable();
    }
}

void SnifferApp::drawConversations() {
    const float S = ImGui::GetFontSize() / 16.0f;
    if (ImGui::BeginTable("##conv", 4,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX,
                          ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("端点 A", ImGuiTableColumnFlags_WidthFixed, 160 * S);
        ImGui::TableSetupColumn("端点 B", ImGuiTableColumnFlags_WidthFixed, 160 * S);
        ImGui::TableSetupColumn("报文", ImGuiTableColumnFlags_WidthFixed, 70 * S);
        ImGui::TableSetupColumn("字节", ImGuiTableColumnFlags_WidthFixed, 84 * S);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const auto& c : conversationCache_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(c.a.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(c.b.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%llu", static_cast<unsigned long long>(c.packets));
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(nps::formatBytes(c.bytes).c_str());
        }
        ImGui::EndTable();
    }
}

void SnifferApp::drawProcessTable() {
    const float S = ImGui::GetFontSize() / 16.0f;
    ImGui::TextDisabled("%s", analyzer_.processStatus().c_str());
    if (ImGui::BeginTable("##proc", 5,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX,
                          ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 56 * S);
        ImGui::TableSetupColumn("进程", ImGuiTableColumnFlags_WidthFixed, 130 * S);
        ImGui::TableSetupColumn("本地", ImGuiTableColumnFlags_WidthFixed, 140 * S);
        ImGui::TableSetupColumn("远端", ImGuiTableColumnFlags_WidthFixed, 140 * S);
        ImGui::TableSetupColumn("状态", ImGuiTableColumnFlags_WidthFixed, 90 * S);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const auto& c : processCache_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", c.pid);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(c.name.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s:%u", c.localIp.c_str(), c.localPort);
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%s:%u", c.remoteIp.c_str(), c.remotePort);
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(c.state.c_str());
        }
        ImGui::EndTable();
    }
}

void SnifferApp::drawSidePanel(const ImVec2& size) {
    (void)size;
    // 首次绘制时按启动参数选中指定标签
    const ImGuiTabItemFlags sel = tabApplied_ ? 0 : ImGuiTabItemFlags_SetSelected;
    if (ImGui::BeginTabBar("##sidetabs")) {
        if (ImGui::BeginTabItem("TCP 流", nullptr,
                                sideTab_ == 0 ? sel : 0)) {
            drawStreamTable();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("协议分层", nullptr,
                                sideTab_ == 1 ? sel : 0)) {
            drawHierarchy();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("会话", nullptr,
                                sideTab_ == 2 ? sel : 0)) {
            drawConversations();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("进程", nullptr,
                                sideTab_ == 3 ? sel : 0)) {
            drawProcessTable();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    tabApplied_ = true;
}

void SnifferApp::drawStatusBar() {
    auto lock = analyzer_.lock();
    const size_t total = analyzer_.packetsUnlocked().size();
    const nps::CaptureStats st = analyzer_.statsUnlocked();
    const size_t streams = analyzer_.streamCountUnlocked();
    lock.unlock();

    const auto pcapStats = capture_.pcapStats();
    ImGui::Text("捕获 %zu  |  显示 %d  |  TCP %llu / UDP %llu / ICMP %llu  |  HTTP %llu / DNS %llu  "
                "|  TCP 流 %zu  |  畸形 %llu  |  libpcap 收包 %llu 丢包 %llu",
                total, static_cast<int>(rows_.size()),
                static_cast<unsigned long long>(st.tcpPackets),
                static_cast<unsigned long long>(st.udpPackets),
                static_cast<unsigned long long>(st.icmpPackets),
                static_cast<unsigned long long>(st.httpPackets),
                static_cast<unsigned long long>(st.dnsPackets), streams,
                static_cast<unsigned long long>(st.malformed),
                static_cast<unsigned long long>(pcapStats.received),
                static_cast<unsigned long long>(pcapStats.dropped));
    if (!statusMessage_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.55f, 0.78f, 0.55f, 1.0f), "   %s", statusMessage_.c_str());
    }
}

void SnifferApp::drawDialogs() {
    if (ImGui::BeginPopupModal("文件路径", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted(dialogMode_ == 1 ? "输入要打开的 pcap 路径" : "输入保存路径");
        ImGui::SetNextItemWidth(520);
        ImGui::InputText("##path", pathBuf_, sizeof(pathBuf_));
        if (ImGui::Button("确定", ImVec2(90, 0))) {
            std::string error;
            if (dialogMode_ == 1) {
                if (!openFile(pathBuf_, error) && !error.empty()) statusMessage_ = error;
                if (!filterText_.empty()) applyDisplayFilter(filterText_);
            } else {
                if (!exportPcap(pathBuf_, error)) statusMessage_ = error;
                else statusMessage_ = std::string("已保存到 ") + pathBuf_;
            }
            dialogMode_ = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("取消", ImVec2(90, 0))) {
            dialogMode_ = 0;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

// 演示脚本：按录制时间轴推进，保证同一秒数下界面状态可复现
void SnifferApp::demoTick(double t) {
    if (demoDir_.empty()) return;

    auto openTest = [this](const char* name) {
        std::string err;
        openFile(demoDir_ + name, err);
        if (!err.empty()) statusMessage_ = err;
    };
    auto pick = [this](const std::function<bool(const nps::Packet&)>& pred) {
        const int row = findRow(pred);
        if (row >= 0) selectRow(row);
    };
    auto setTab = [this](int tab) {
        if (sideTab_ == tab) return;
        sideTab_ = tab;
        tabApplied_ = false;  // 让下一次绘制把新标签页设为选中
    };

    int stage = 0;
    if (t >= 31.0) stage = 11;
    else if (t >= 28.0) stage = 10;
    else if (t >= 25.0) stage = 9;
    else if (t >= 22.0) stage = 8;
    else if (t >= 19.0) stage = 7;
    else if (t >= 16.0) stage = 6;
    else if (t >= 13.0) stage = 5;
    else if (t >= 10.0) stage = 4;
    else if (t >= 6.5) stage = 3;
    else if (t >= 3.0) stage = 2;
    else stage = 1;
    if (stage == demoStage_) return;
    demoStage_ = stage;

    switch (stage) {
        case 1:
            demoCaption_ = "载入 http_basic.pcap：TCP 三次握手 + HTTP 请求/响应";
            setTab(0);
            selectRow(0);
            break;
        case 2: {
            demoCaption_ = "选中 HTTP 请求：协议字段树与十六进制逐字节联动";
            pick([](const nps::Packet& p) {
                return p.appProto == "HTTP" && p.info.rfind("GET", 0) == 0;
            });
            nps::Packet pkt;
            if (selectedRow_ >= 0 && packetAt(selectedRow_, pkt)) {
                highlightOffset_ = static_cast<int>(pkt.payloadOffset);
                highlightLength_ = static_cast<int>(pkt.payloadLength);
                scrollToHighlight_ = true;
            }
            break;
        }
        case 3:
            demoCaption_ = "TCP 流视图：握手 RTT、载荷字节、重传/乱序计数与 HTTP 还原";
            setTab(0);
            break;
        case 4:
            demoCaption_ = "打开 tcp_reorder.pcap：重传报文黄色高亮";
            openTest("tcp_reorder.pcap");
            setTab(0);
            pick([](const nps::Packet& p) { return p.retransmission; });
            break;
        case 5:
            demoCaption_ = "乱序报文：按 SEQ 重排后仍能还原出完整 HTTP 报文";
            pick([](const nps::Packet& p) { return p.outOfOrder; });
            break;
        case 6:
            demoCaption_ = "mixed.pcap：DNS 查询与响应解析";
            openTest("mixed.pcap");
            setTab(0);
            pick([](const nps::Packet& p) { return p.appProto == "DNS"; });
            break;
        case 7:
            demoCaption_ = "TLS ClientHello：从明文 SNI 识别访问的域名";
            pick([](const nps::Packet& p) { return p.appProto == "TLS"; });
            break;
        case 8:
            demoCaption_ = "显示过滤器：http or dns，只保留应用层相关报文";
            applyDisplayFilter("http or dns");
            selectRow(0);
            break;
        case 9:
            demoCaption_ = "协议分层统计：Frame → Ethernet → IPv4/IPv6 → TCP/UDP → HTTP/DNS/TLS";
            applyDisplayFilter("");
            setTab(1);
            break;
        case 10:
            demoCaption_ = "会话统计：按字节数排序的 Top 会话";
            setTab(2);
            break;
        case 11:
            demoCaption_ = "TCP 流表：进程归因列在实时抓包时显示进程名与 PID";
            setTab(0);
            pick([](const nps::Packet& p) { return p.l4 == nps::L4Proto::Tcp; });
            break;
        default:
            break;
    }
}

void SnifferApp::render() {
    refreshRows();
    const double now = ImGui::GetTime();
    if (cacheTime_ < 0.0 || now - cacheTime_ > 0.8) {
        cacheTime_ = now;
        {
            auto lock = analyzer_.lock();
            streamCache_ = analyzer_.streamsUnlocked();
            hierarchyCache_ = analyzer_.hierarchyUnlocked();
            conversationCache_ = analyzer_.conversationsUnlocked();
            processCache_ = analyzer_.processConnectionsUnlocked();
        }
        std::sort(conversationCache_.begin(), conversationCache_.end(),
                  [](const nps::ConversationStat& a, const nps::ConversationStat& b) {
                      return a.bytes > b.bytes;
                  });
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const ImVec2 origin = vp->WorkPos;
    const ImVec2 total = vp->WorkSize;
    ImGuiStyle& style = ImGui::GetStyle();
    ImGuiIO& io = ImGui::GetIO();

    const ImGuiWindowFlags paneFlags =
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse;
    const ImGuiWindowFlags scrollPaneFlags =
        paneFlags & ~(ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);

    // 顶部工具栏（高度自适应）
    ImGui::SetNextWindowPos(origin);
    ImGui::SetNextWindowSize(ImVec2(total.x, 0.0f), ImGuiCond_Always);
    ImGui::Begin("##topbar", nullptr, paneFlags | ImGuiWindowFlags_AlwaysAutoResize);
    drawTopBar();
    drawFilterBar();
    const float topH = ImGui::GetWindowSize().y;
    ImGui::End();

    // 底部状态栏
    const float statusH =
        ImGui::GetTextLineHeightWithSpacing() + style.WindowPadding.y * 2.0f + 2.0f;
    ImGui::SetNextWindowPos(ImVec2(origin.x, origin.y + total.y - statusH));
    ImGui::SetNextWindowSize(ImVec2(total.x, statusH), ImGuiCond_Always);
    ImGui::Begin("##statusbar", nullptr, paneFlags | ImGuiWindowFlags_NoTitleBar);
    drawStatusBar();
    ImGui::End();

    const float gap = 6.0f;
    const float contentY = origin.y + topH;
    const float contentH = total.y - topH - statusH;
    const float contentW = total.x;

    // 比例 -> 几何
    auto geometry = [&](float& sideW, float& leftW, float& listH, float& treeW) {
        sideW = contentW * sideRatio_;
        leftW = contentW - sideW - gap;
        listH = contentH * listRatio_;
        treeW = leftW * treeRatio_;
    };
    float sideW = 0, leftW = 0, listH = 0, treeW = 0;
    geometry(sideW, leftW, listH, treeW);

    // 分隔条拖动（面板之间的空隙）
    const float splitX1 = origin.x + leftW;             // 左列 | 右侧栏
    const float splitY1 = contentY + listH;             // 报文列表 | 详情
    const float splitX2 = origin.x + treeW;             // 详情树 | 十六进制
    const bool inY = io.MousePos.y >= contentY && io.MousePos.y <= contentY + contentH;

    const bool hoverX1 = inY && std::fabs(io.MousePos.x - splitX1 - gap * 0.5f) <= gap * 0.5f + 3.0f;
    const bool hoverX2 = std::fabs(io.MousePos.x - splitX2 - gap * 0.5f) <= gap * 0.5f + 3.0f &&
                         io.MousePos.y >= splitY1;
    const bool hoverY1 = io.MousePos.x >= origin.x && io.MousePos.x <= origin.x + leftW &&
                         std::fabs(io.MousePos.y - splitY1 - gap * 0.5f) <= gap * 0.5f + 3.0f;

    if (hoverX1 || hoverX2) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    if (hoverY1) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);

    if (io.MouseClicked[0]) {
        if (hoverX1) dragSplit_ = 1;
        else if (hoverY1) dragSplit_ = 2;
        else if (hoverX2) dragSplit_ = 3;
    }
    if (!io.MouseDown[0]) dragSplit_ = 0;
    if (dragSplit_ == 1 && contentW > 1.0f) {
        sideRatio_ = std::clamp(sideRatio_ - io.MouseDelta.x / contentW, 0.2f, 0.7f);
        geometry(sideW, leftW, listH, treeW);
    } else if (dragSplit_ == 2 && contentH > 1.0f) {
        listRatio_ = std::clamp(listRatio_ + io.MouseDelta.y / contentH, 0.2f, 0.84f);
        geometry(sideW, leftW, listH, treeW);
    } else if (dragSplit_ == 3 && leftW > 1.0f) {
        treeRatio_ = std::clamp(treeRatio_ + io.MouseDelta.x / leftW, 0.18f, 0.78f);
        geometry(sideW, leftW, listH, treeW);
    }

    const float detailY = contentY + listH + gap;
    const float detailH = contentH - listH - gap;
    const float hexW = leftW - treeW - gap;

    ImGui::SetNextWindowPos(ImVec2(origin.x, contentY));
    ImGui::SetNextWindowSize(ImVec2(leftW, listH));
    ImGui::Begin("报文列表", nullptr, paneFlags);
    drawPacketTable(ImGui::GetContentRegionAvail());
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(origin.x, detailY));
    ImGui::SetNextWindowSize(ImVec2(treeW, detailH));
    ImGui::Begin("协议详情", nullptr, scrollPaneFlags);
    drawDetailPane(ImGui::GetContentRegionAvail());
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(origin.x + treeW + gap, detailY));
    ImGui::SetNextWindowSize(ImVec2(hexW, detailH));
    ImGui::Begin("十六进制 / 原始数据", nullptr, paneFlags);
    drawHexView(ImGui::GetContentRegionAvail());
    ImGui::End();

    ImGui::SetNextWindowPos(ImVec2(origin.x + leftW + gap, contentY));
    ImGui::SetNextWindowSize(ImVec2(sideW, contentH));
    ImGui::Begin("TCP 流 / 协议统计", nullptr, paneFlags);
    drawSidePanel(ImGui::GetContentRegionAvail());
    ImGui::End();

    drawDialogs();

    // 录制模式下的旁白字幕
    if (!options_.recordDir.empty() && !demoCaption_.empty()) {
        ImDrawList* fg = ImGui::GetForegroundDrawList();
        const ImVec2 textSize = ImGui::CalcTextSize(demoCaption_.c_str());
        const float padX = 18.0f * (ImGui::GetFontSize() / 16.0f);
        const float padY = 9.0f * (ImGui::GetFontSize() / 16.0f);
        const ImVec2 boxMin((total.x - textSize.x) * 0.5f - padX,
                            origin.y + total.y - 74.0f - textSize.y - padY);
        const ImVec2 boxMax(boxMin.x + textSize.x + padX * 2.0f,
                            boxMin.y + textSize.y + padY * 2.0f);
        fg->AddRectFilled(boxMin, boxMax, IM_COL32(12, 16, 22, 220), 6.0f);
        fg->AddRect(boxMin, boxMax, IM_COL32(90, 150, 200, 220), 6.0f);
        fg->AddText(ImVec2(boxMin.x + padX, boxMin.y + padY), IM_COL32(226, 232, 240, 255),
                    demoCaption_.c_str());
    }

    ImGui::PopStyleVar();
}

