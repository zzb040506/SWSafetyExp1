cmake_minimum_required(VERSION 3.16)
project(NpsSniffer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O2")

# libpcap：Linux/macOS 直接用系统库，Windows 需要先安装 Npcap SDK 并设置
# NPCAP_SDK_DIR 环境变量或 -DNPCAP_SDK_DIR=<path>
if(WIN32)
    if(NOT DEFINED NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
        set(NPCAP_SDK_DIR $ENV{NPCAP_SDK_DIR})
    endif()
    if(NOT NPCAP_SDK_DIR)
        message(FATAL_ERROR "Windows 构建需要 Npcap SDK：cmake -DNPCAP_SDK_DIR=<Npcap SDK 路径>")
    endif()
    set(PCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
    find_library(PCAP_LIBRARY wpcap PATHS "${NPCAP_SDK_DIR}/Lib/x64" NO_DEFAULT_PATH)
    find_library(WS2_LIBRARY ws2_32 REQUIRED)
else()
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY pcap)
endif()

if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "未找到 libpcap，请先安装（macOS/Linux 通常自带，Linux 可 apt install libpcap-dev）")
endif()

add_library(nps_core STATIC
    src/core/util.cpp
    src/core/types.cpp
    src/core/dissector.cpp
    src/core/filter.cpp
    src/core/stream_tracker.cpp
    src/core/process_map.cpp
    src/core/capture.cpp
    src/core/analyzer.cpp
)
target_include_directories(nps_core PUBLIC src ${PCAP_INCLUDE_DIR})
target_link_libraries(nps_core PUBLIC ${PCAP_LIBRARY})
find_package(Threads REQUIRED)
target_link_libraries(nps_core PUBLIC Threads::Threads)
if(WIN32)
    target_link_libraries(nps_core PUBLIC ${WS2_LIBRARY} iphlpapi)
endif()

add_executable(nps-cli src/cli/main.cpp)
target_link_libraries(nps-cli PRIVATE nps_core)

# GUI 依赖 SDL2 + Dear ImGui，找不到 SDL2 时只构建 CLI
find_path(SDL2_INCLUDE_DIR SDL.h PATH_SUFFIXES SDL2)
find_library(SDL2_LIBRARY SDL2)
if(SDL2_INCLUDE_DIR AND SDL2_LIBRARY)
    add_executable(nps-gui
        src/gui/main.cpp
        src/gui/app.cpp
        third_party/imgui/imgui.cpp
        third_party/imgui/imgui_draw.cpp
        third_party/imgui/imgui_tables.cpp
        third_party/imgui/imgui_widgets.cpp
        third_party/imgui/backends/imgui_impl_sdl2.cpp
        third_party/imgui/backends/imgui_impl_sdlrenderer2.cpp
        third_party/imgui/misc/cpp/imgui_stdlib.cpp
    )
    target_include_directories(nps-gui PRIVATE
        ${SDL2_INCLUDE_DIR}
        third_party/imgui
        third_party/imgui/backends
        third_party/imgui/misc/cpp
        third_party/stb
    )
    target_link_libraries(nps-gui PRIVATE nps_core ${SDL2_LIBRARY})
    if(APPLE)
        set_target_properties(nps-gui PROPERTIES MACOSX_BUNDLE FALSE)
    endif()
    message(STATUS "SDL2 已找到，将构建 nps-gui")
else()
    message(STATUS "未找到 SDL2，仅构建 nps-cli")
endif()
