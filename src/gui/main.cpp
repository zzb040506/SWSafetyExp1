// GUI 入口：SDL2 + Dear ImGui，支持 --read/--filter/--screenshot 等参数
#include <SDL.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "app.h"
#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_sdlrenderer2.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

namespace {

bool fileExists(const char* path) {
    if (!path) return false;
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fclose(f);
    return true;
}

void applyStyle() {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.FramePadding = ImVec2(7, 4);
    style.ItemSpacing = ImVec2(7, 5);

    ImVec4* c = style.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(0.078f, 0.086f, 0.102f, 1.00f);
    c[ImGuiCol_ChildBg] = ImVec4(0.098f, 0.106f, 0.125f, 1.00f);
    c[ImGuiCol_PopupBg] = ImVec4(0.11f, 0.12f, 0.14f, 1.00f);
    c[ImGuiCol_Border] = ImVec4(0.20f, 0.22f, 0.26f, 1.00f);
    c[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.165f, 0.19f, 1.00f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.22f, 0.26f, 1.00f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.24f, 0.27f, 0.32f, 1.00f);
    c[ImGuiCol_TitleBg] = ImVec4(0.08f, 0.09f, 0.11f, 1.00f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.10f, 0.11f, 0.13f, 1.00f);
    c[ImGuiCol_MenuBarBg] = ImVec4(0.10f, 0.11f, 0.13f, 1.00f);
    c[ImGuiCol_Header] = ImVec4(0.16f, 0.24f, 0.34f, 1.00f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.20f, 0.30f, 0.42f, 1.00f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.24f, 0.36f, 0.50f, 1.00f);
    c[ImGuiCol_Button] = ImVec4(0.16f, 0.32f, 0.46f, 1.00f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.21f, 0.40f, 0.56f, 1.00f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.26f, 0.48f, 0.66f, 1.00f);
    c[ImGuiCol_Tab] = ImVec4(0.13f, 0.15f, 0.18f, 1.00f);
    c[ImGuiCol_TabHovered] = ImVec4(0.22f, 0.34f, 0.46f, 1.00f);
    c[ImGuiCol_TabSelected] = ImVec4(0.18f, 0.28f, 0.38f, 1.00f);
    c[ImGuiCol_Text] = ImVec4(0.88f, 0.90f, 0.93f, 1.00f);
    c[ImGuiCol_TextDisabled] = ImVec4(0.52f, 0.56f, 0.62f, 1.00f);
    c[ImGuiCol_Separator] = ImVec4(0.20f, 0.22f, 0.26f, 1.00f);
    c[ImGuiCol_TableHeaderBg] = ImVec4(0.13f, 0.15f, 0.18f, 1.00f);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(0.105f, 0.115f, 0.135f, 1.00f);
}

// 加载中文字体；失败时回退到 ImGui 默认字体
ImFont* loadUiFont(ImGuiIO& io, float size) {
    // 汉字全集 + 全角标点（ChineseFull 不含括号等全角符号）
    static ImVector<ImWchar> ranges;
    if (ranges.empty()) {
        static const ImWchar extra[] = {0x2000, 0x206F, 0x3000, 0x303F, 0xFF00, 0xFFEF, 0};
        ImFontGlyphRangesBuilder builder;
        builder.AddRanges(io.Fonts->GetGlyphRangesChineseFull());
        builder.AddRanges(extra);
        builder.BuildRanges(&ranges);
    }
    const char* candidates[] = {
#if defined(_WIN32)
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/simhei.ttf",
#elif defined(__APPLE__)
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
#else
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
#endif
        nullptr};
    for (int i = 0; candidates[i]; ++i) {
        if (!fileExists(candidates[i])) continue;
        ImFontConfig cfg;
        cfg.OversampleH = 2;
        cfg.OversampleV = 1;
        cfg.PixelSnapH = true;
        ImFont* font = io.Fonts->AddFontFromFileTTF(candidates[i], size, &cfg, ranges.Data);
        if (font) return font;
    }
    io.Fonts->AddFontDefault();
    return nullptr;
}

ImFont* loadMonoFont(ImGuiIO& io, float size) {
    const char* candidates[] = {
#if defined(_WIN32)
        "C:/Windows/Fonts/consola.ttf",
#elif defined(__APPLE__)
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFNSMono.ttf",
#else
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
#endif
        nullptr};
    for (int i = 0; candidates[i]; ++i) {
        if (!fileExists(candidates[i])) continue;
        ImFontConfig cfg;
        cfg.OversampleH = 1;
        cfg.PixelSnapH = true;
        ImFont* font = io.Fonts->AddFontFromFileTTF(candidates[i], size, &cfg);
        if (font) return font;
    }
    return nullptr;
}

bool readFrame(SDL_Renderer* renderer, std::vector<unsigned char>& pixels, int& w, int& h) {
    SDL_GetRendererOutputSize(renderer, &w, &h);
    pixels.resize(static_cast<size_t>(w) * h * 4);
    if (SDL_RenderReadPixels(renderer, nullptr, SDL_PIXELFORMAT_RGBA32, pixels.data(), w * 4) != 0) {
        std::fprintf(stderr, "读取帧缓冲失败: %s\n", SDL_GetError());
        return false;
    }
    stbi_flip_vertically_on_write(0);
    return true;
}

void saveScreenshot(SDL_Renderer* renderer, const std::string& path, bool verbose = true) {
    std::vector<unsigned char> pixels;
    int w = 0, h = 0;
    if (!readFrame(renderer, pixels, w, h)) return;
    if (stbi_write_png(path.c_str(), w, h, 4, pixels.data(), w * 4)) {
        if (verbose) std::printf("截图已保存: %s (%dx%d)\n", path.c_str(), w, h);
    } else {
        std::fprintf(stderr, "写入 PNG 失败\n");
    }
}

// 录制帧用 JPEG：体积与编码耗时都远小于 PNG，适合后续直接编码视频
void saveFrameJpeg(SDL_Renderer* renderer, const std::string& path, int quality) {
    std::vector<unsigned char> pixels;
    int w = 0, h = 0;
    if (!readFrame(renderer, pixels, w, h)) return;
    if (!stbi_write_jpg(path.c_str(), w, h, 4, pixels.data(), quality)) {
        std::fprintf(stderr, "写入 JPEG 失败: %s\n", path.c_str());
    }
}

}  // namespace

int main(int argc, char** argv) {
    AppOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "参数 %s 缺少取值\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--read") options.openPcap = next("--read");
        else if (a == "--filter") options.displayFilter = next("--filter");
        else if (a == "--bpf") options.bpf = next("--bpf");
        else if (a == "--device") options.device = next("--device");
        else if (a == "--screenshot") options.screenshot = next("--screenshot");
        else if (a == "--select") options.selectRow = std::atoi(next("--select").c_str());
        else if (a == "--tab") options.tab = std::atoi(next("--tab").c_str());
        else if (a == "--record") options.recordDir = next("--record");
        else if (a == "--record-fps") options.recordFps = std::atoi(next("--record-fps").c_str());
        else if (a == "--record-seconds")
            options.recordSeconds = std::atof(next("--record-seconds").c_str());
        else if (a == "--capture-seconds")
            options.captureSeconds = std::atof(next("--capture-seconds").c_str());
        else if (a == "--help" || a == "-h") {
            std::printf(
                "NPS Sniffer GUI\n"
                "  --read <pcap>            启动时载入 pcap\n"
                "  --filter <expr>          设置显示过滤器\n"
                "  --bpf <expr>             设置 BPF 过滤器\n"
                "  --device <name>          指定网卡并开始实时抓包\n"
                "  --capture-seconds <N>    实时抓包时长（秒）\n"
                "  --select <row>           选中第 N 行（从 0 开始）\n"
                "  --tab <0-3>              右侧面板：0 流 1 分层 2 会话 3 进程\n"
                "  --screenshot <png>       渲染若干帧后截图退出\n"
                "  --record <dir>           按演示脚本逐帧输出 PNG（用于录制视频）\n"
                "  --record-fps <N>         录制帧率，默认 24\n"
                "  --record-seconds <N>     录制时长，默认 34 秒\n");
            return 0;
        }
    }

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        std::fprintf(stderr, "SDL_Init 失败: %s\n", SDL_GetError());
        return 1;
    }
    SDL_Window* window = SDL_CreateWindow(
        "NPS Sniffer — 网络嗅探与协议分析", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        1480, 920, SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    if (!window) {
        std::fprintf(stderr, "创建窗口失败: %s\n", SDL_GetError());
        return 1;
    }
    SDL_Renderer* renderer = SDL_CreateRenderer(
        window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
    }
    if (!renderer) {
        std::fprintf(stderr, "创建渲染器失败: %s\n", SDL_GetError());
        return 1;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;  // 不写 imgui.ini，避免提交物夹带本地布局
    applyStyle();

    float dpiScale = 1.0f;
    {
        int ww = 0, wh = 0, rw = 0, rh = 0;
        SDL_GetWindowSize(window, &ww, &wh);
        SDL_GetRendererOutputSize(renderer, &rw, &rh);
        if (ww > 0) dpiScale = static_cast<float>(rw) / ww;
    }
    // 直接按物理像素布局，保证 Retina 下字体与截图都清晰
    loadUiFont(io, 16.0f * dpiScale);
    ImFont* mono = loadMonoFont(io, 14.0f * dpiScale);

    ImGui_ImplSDL2_InitForSDLRenderer(window, renderer);
    ImGui_ImplSDLRenderer2_Init(renderer);

    SnifferApp app(options);
    app.setMonoFont(mono);

    bool done = false;
    int frame = 0;
    Uint64 startTicks = SDL_GetTicks64();
    bool captureStopped = false;

    if (!options.recordDir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(options.recordDir, ec);
        if (ec) {
            std::fprintf(stderr, "无法创建录制目录 %s: %s\n", options.recordDir.c_str(),
                         ec.message().c_str());
            return 1;
        }
    }
    int recordFrame = 0;
    const int recordTotal = static_cast<int>(options.recordSeconds * options.recordFps + 0.5);

    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE &&
                event.window.windowID == SDL_GetWindowID(window)) {
                done = true;
            }
        }

        if (options.captureSeconds > 0 && !captureStopped) {
            const double elapsed = static_cast<double>(SDL_GetTicks64() - startTicks) / 1000.0;
            if (elapsed > options.captureSeconds) {
                app.stopLiveCapture();
                captureStopped = true;
            }
        }

        if (!options.recordDir.empty()) {
            app.demoTick(static_cast<double>(recordFrame) / options.recordFps);
        }

        ImGui_ImplSDLRenderer2_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        {
            int rw = 0, rh = 0;
            SDL_GetRendererOutputSize(renderer, &rw, &rh);
            // 全部按物理像素布局：DisplaySize 就是帧缓冲尺寸，缩放比固定为 1
            io.DisplaySize = ImVec2(static_cast<float>(rw), static_cast<float>(rh));
            io.DisplayFramebufferScale = ImVec2(1.0f, 1.0f);
            if (dpiScale != 1.0f) {
                // SDL 鼠标坐标以逻辑点为单位，这里换算到物理像素
                io.AddMousePosEvent(io.MousePos.x * dpiScale, io.MousePos.y * dpiScale);
            }
        }
        ImGui::NewFrame();
        app.render();
        ImGui::Render();

        SDL_SetRenderDrawColor(renderer, 18, 20, 24, 255);
        SDL_RenderClear(renderer);
        ImGui_ImplSDLRenderer2_RenderDrawData(ImGui::GetDrawData(), renderer);
        ++frame;

        // 必须在 Present 之前读回像素，否则 macOS 上可能拿到已被回收的帧缓冲
        if (!options.screenshot.empty() && frame == 45) {
            saveScreenshot(renderer, options.screenshot);
            done = true;
        }
        if (!options.recordDir.empty()) {
            if (recordFrame >= recordTotal) {
                done = true;
                std::printf("录制完成: %d 帧 -> %s\n", recordFrame, options.recordDir.c_str());
            } else {
                char path[1024];
                std::snprintf(path, sizeof(path), "%s/frame_%05d.jpg",
                              options.recordDir.c_str(), recordFrame);
                saveFrameJpeg(renderer, path, 92);
                ++recordFrame;
            }
        }
        SDL_RenderPresent(renderer);
    }

    ImGui_ImplSDLRenderer2_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
