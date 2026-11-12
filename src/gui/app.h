// GUI 应用状态与绘制（SDL2 + Dear ImGui）
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/analyzer.h"
#include "core/capture.h"
#include "core/filter.h"
#include "imgui.h"

struct AppOptions {
    std::string openPcap;
    std::string displayFilter;
    std::string bpf;
    std::string device;
    std::string screenshot;
    int selectRow = 0;
    int tab = 0;              // 0=TCP 流 1=协议分层 2=会话 3=进程
    double captureSeconds = 0;
    std::string recordDir;    // 非空时进入演示录制模式，逐帧写 PNG
    int recordFps = 24;
    double recordSeconds = 34.0;
};

class SnifferApp {
public:
    explicit SnifferApp(const AppOptions& options);
    ~SnifferApp();

    void render();
    bool wantQuit() const { return wantQuit_; }
    void setMonoFont(ImFont* font) { monoFont_ = font ? font : ImGui::GetFont(); }
    void stopLiveCapture() { stopLive(); }
    bool capturing() const { return capturing_; }
    // 演示脚本：按录制时间轴切换 pcap、选中报文、切换标签页
    void demoTick(double seconds);

private:
    void drawTopBar();
    void drawFilterBar();
    void drawPacketTable(const ImVec2& size);
    void drawDetailPane(const ImVec2& size);
    void drawHexView(const ImVec2& size);
    void drawSidePanel(const ImVec2& size);
    void drawStreamTable();
    void drawSequenceDiagram();
    void drawHierarchy();
    void drawConversations();
    void drawProcessTable();
    void drawStatusBar();
    void drawFieldNode(const nps::FieldNode& node, int depth);
    void drawDialogs();
    bool packetAt(int row, nps::Packet& out) const;
    int findRow(const std::function<bool(const nps::Packet&)>& pred) const;
    void updateDetail(int row);

    void refreshRows();
    void applyDisplayFilter(const std::string& expression);
    bool openFile(const std::string& path, std::string& error);
    void startLive(const std::string& device);
    void stopLive();
    void selectRow(int row);
    void clearAll();
    bool exportPcap(const std::string& path, std::string& error);

    nps::Analyzer analyzer_;
    nps::CaptureEngine capture_;
    nps::DisplayFilter filter_;
    AppOptions options_;

    std::vector<int64_t> rows_;
    size_t scanned_ = 0;
    double firstTs_ = -1.0;
    int selectedRow_ = -1;
    int selectedStream_ = -1;
    int highlightOffset_ = -1;
    int highlightLength_ = 0;

    int displayOffset_ = -1;  // 当前详情对应的报文下标
    std::vector<uint8_t> hexData_;
    nps::Packet detailPacket_;
    bool detailValid_ = false;
    bool scrollDetail_ = false;

    std::string filterError_;
    std::string statusMessage_;
    double statusMessageTime_ = 0.0;
    bool capturing_ = false;
    bool attribution_ = false;
    std::string currentFile_;

    std::vector<nps::CaptureEngine::DeviceInfo> devices_;
    int deviceIndex_ = 0;
    std::string bpfText_;
    std::string filterText_;

    ImFont* monoFont_ = nullptr;
    float listRatio_ = 0.45f;
    float treeRatio_ = 0.40f;
    float sideRatio_ = 0.36f;
    int dragSplit_ = 0;  // 0 无 1 左列/右栏 2 列表/详情 3 详情/十六进制
    int sideTab_ = 0;
    bool tabApplied_ = false;
    bool wantQuit_ = false;
    bool scrollToHighlight_ = false;
    char pathBuf_[512] = {0};
    int dialogMode_ = 0;  // 0 无 1 打开 2 保存

    // 缓存快照，避免每帧跨线程复制大对象
    std::vector<nps::TcpStream> streamCache_;
    std::vector<std::pair<std::string, nps::ProtoStat>> hierarchyCache_;
    std::vector<nps::ConversationStat> conversationCache_;
    std::vector<nps::ProcessConn> processCache_;
    double cacheTime_ = -1.0;

    // 演示录制
    std::string demoDir_;
    std::string demoCaption_;
    int demoStage_ = 0;
};
