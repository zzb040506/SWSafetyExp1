-- nps.lua —— NPS Sniffer 的 Wireshark Lua 插件（Wireshark 二次开发）
--
-- 作用：把 nps-cli 的逐帧分析结果（TCP 流编号、重传/乱序判定、进程归因）
--       作为可过滤字段注入 Wireshark，使 Wireshark 能够直接按
--       “某进程产生的所有 TCP 流”或“只看重传帧”进行筛选。
--
-- 用法：
--   1) 生成标注：nps-cli --read capture.pcap --procs --annotate capture.tsv
--   2) 安装插件：cp tools/wireshark/nps.lua ~/.local/lib/wireshark/plugins/
--      （Linux/macOS：~/.local/lib/wireshark/plugins/；Windows：
--        %APPDATA%\Wireshark\plugins\）
--   3) 打开 Wireshark → 编辑 → 首选项 → Protocols → NPS Sniffer，
--      把 annotation_file 设为 capture.tsv 的绝对路径
--   4) 过滤栏可用：
--        nps.proc.name == "curl"         某进程的全部 TCP 报文
--        nps.proc.pid == 1234            按 PID 过滤
--        nps.stream == 3                 只看第 3 条 TCP 流
--        nps.tcp.retransmission == 1     只看重传帧
--        nps.tcp.out_of_order == 1       只看乱序帧
--
-- 说明：标注按 pcap 帧号一一对应，因此生成标注时不要给 nps-cli 加 --bpf，
--       否则两侧帧号会错位。

local nps = Proto("nps", "NPS Sniffer 旁路标注")

local f_stream = ProtoField.uint32("nps.stream", "NPS TCP 流编号", base.DEC)
local f_retrans = ProtoField.bool("nps.tcp.retransmission", "NPS 重传")
local f_ooo = ProtoField.bool("nps.tcp.out_of_order", "NPS 乱序")
local f_pid = ProtoField.int32("nps.proc.pid", "NPS 进程 PID", base.DEC)
local f_proc = ProtoField.string("nps.proc.name", "NPS 进程名")

nps.fields = { f_stream, f_retrans, f_ooo, f_pid, f_proc }

nps.prefs.annotation_file =
    Pref.string("annotation_file", "", "nps-cli --annotate 生成的 TSV 文件绝对路径")

local annotations = {}
local loaded_path = nil
local frame_field = Field.new("frame.number")

local function load_annotations()
    annotations = {}
    loaded_path = nps.prefs.annotation_file
    if loaded_path == nil or loaded_path == "" then
        return 0
    end
    local fh = io.open(loaded_path, "r")
    if fh == nil then
        return 0
    end

    local count = 0
    for line in fh:lines() do
        -- 按制表符切分并保留空字段（进程名为空时也是一个字段）
        local cols = {}
        local pos = 1
        while true do
            local sep = string.find(line, "\t", pos, true)
            if sep == nil then
                cols[#cols + 1] = string.sub(line, pos)
                break
            end
            cols[#cols + 1] = string.sub(line, pos, sep - 1)
            pos = sep + 1
        end
        local frame = tonumber(cols[1])
        -- 跳过表头与残缺行
        if frame ~= nil and #cols >= 6 then
            annotations[frame] = {
                stream = tonumber(cols[2]) or -1,
                retrans = cols[3] == "1",
                ooo = cols[4] == "1",
                pid = tonumber(cols[5]) or -1,
                proc = cols[6],
            }
            count = count + 1
        end
    end
    fh:close()
    return count
end

-- 首选项变更后重新载入标注文件
function nps.prefs_changed()
    local count = load_annotations()
    if loaded_path ~= nil and loaded_path ~= "" then
        print(string.format("NPS 插件：已从 %s 载入 %d 帧标注", loaded_path, count))
    end
end

function nps.dissector(buffer, pinfo, tree)
    if loaded_path == nil then
        load_annotations()
    end
    local frame_no = frame_field()
    if frame_no == nil then
        return
    end

    local a = annotations[tonumber(tostring(frame_no))]
    if a == nil then
        return
    end

    -- 用零长度范围挂载，避免把整个报文染成本插件的字段
    local item = tree:add(nps, buffer(0, 0))
    item:add(f_stream, a.stream)
    item:add(f_pid, a.pid)
    if a.proc ~= nil and a.proc ~= "" then
        item:add(f_proc, a.proc)
    end
    if a.retrans then
        item:add(f_retrans, true)
    end
    if a.ooo then
        item:add(f_ooo, true)
    end
end

register_postdissector(nps)