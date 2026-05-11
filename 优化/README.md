# SVC Monitor — Memory Analyzer & Detection Reverser

> Pixel 6 (oriole) / ARM64 / Android 12 / kernel 5.10.43 / KernelPatch v0.10.7

## 架构概览

```
┌──────────────────────────────────────────────────┐
│  Web Frontend (mem_analyzer.html)                 │
│  8 tabs: Maps | Memory | Disasm | Strings | SVC  │
│          Frida | Watchpoint | Detection Reverser  │
└────────────────────┬─────────────────────────────┘
                     │ REST API
┌────────────────────▼─────────────────────────────┐
│  Flask Backend (mem_api.py)                       │
│  /api/mem/*  → Memory analysis via adb            │
│  /api/dr/*   → Detection Reverser via kpmctl      │
└────────────────────┬─────────────────────────────┘
                     │ adb shell su
┌────────────────────▼─────────────────────────────┐
│  Kernel (KernelPatch Module)                      │
│  svc_monitor.c                                    │
│    ├── mem_monitor.c     (壳读了什么?)             │
│    └── detect_reverser.c (壳在找什么?)             │
└──────────────────────────────────────────────────┘
```

## 快速开始

### 1. 启动 Web 服务

```bash
cd mem_analyzer
pip install flask flask-cors
python3 mem_server.py --port 5001
```

打开 `http://localhost:5001/mem-analyzer`

### 2. 加载内核模块

将 `detect_reverser.c` 和/或 `mem_monitor.c` 集成到 `svc_monitor.c` 中:

```c
// svc_monitor.c 顶部
#include "mem_monitor.c"
#include "detect_reverser.c"
```

详细集成步骤见:
- `kpm/detect_reverser_integration.c`
- `kpm/svc_monitor_integration.c`

### 3. 使用 Detection Reverser

```bash
# 启用, 指定目标 PID
adb shell su -c "kpmctl svc_monitor dr_enable 12345"

# (可选) 指定检测线程 TID
adb shell su -c "kpmctl svc_monitor dr_add_tid 12350"

# 等壳运行检测后, 查看捕获到的 needle
adb shell su -c "kpmctl svc_monitor dr_needles"
```

或者直接在 Web 前端的 **🔬 Detection Reverser** tab 中操作。

## 核心概念

### Detection Reverser vs Memory Monitor

| | mem_monitor.c | detect_reverser.c |
|---|---|---|
| **回答的问题** | 壳读了什么内容? (haystack) | 壳在搜索什么? (needle) |
| **工作原理** | hook read() 扫描返回 buffer | hook syscall 出口, 解引用寄存器提取字符串 |
| **适用场景** | 知道壳在读 maps, 想看读到了什么 | 想知道壳的检测目标是什么字符串 |
| **技术** | buffer 内容匹配 | ARM64 寄存器解引用 + 栈扫描 |
| **输出** | 匹配到的已知字符串和位置 | 发现的未知检测字符串列表 |

### 为什么能抓到 Needle?

壳的自定义 memmem 函数 (不走 libc) 在做逐字节比对时:

1. **needle 指针一定在寄存器或栈上** — ARM64 函数调用约定, 参数通过 x0-x7 传递
2. **检测线程一定会做 syscall** — 读 maps、读内存、最终 kill 自杀
3. **syscall 时寄存器还没被覆盖** — 从调用检测函数到 syscall, 寄存器可能还保留着 needle 指针
4. **特别是 kill() 时** — 检测到目标后调 kill, 此时调用链上一定还有 needle

所以我们在 syscall hook 出口 `dr_capture_context()` 中:
- 遍历 x0-x28, 当作用户态指针解引用
- 如果指向的内存包含可打印字符串 → 记录为潜在 needle
- 同时做二级解引用 (处理 `const char *arr[]` 模式)
- 扫描栈上 512 字节深度的指针

## API 参考

### Detection Reverser API

| 路由 | 方法 | 说明 |
|---|---|---|
| `/api/dr/enable/<pid>` | POST | 启用, body: `{tids?, config?}` |
| `/api/dr/disable` | POST | 禁用 |
| `/api/dr/needles` | GET | ★ 获取捕获的 needle 列表 |
| `/api/dr/status` | GET | 状态统计 |
| `/api/dr/dump/<idx>` | GET | 上下文 dump 详情 |
| `/api/dr/config` | POST | 配置, body: `{stack_scan, full_dump, all_threads}` |
| `/api/dr/clear` | POST | 清除所有数据 |
| `/api/dr/add_tid` | POST | 添加监控 TID, body: `{tid}` |
| `/api/dr/frida_patch` | POST | 生成 Frida patch 脚本 |

### Memory Analysis API

| 路由 | 方法 | 说明 |
|---|---|---|
| `/api/mem/maps/<pid>/smart` | GET | Smart maps 分析 |
| `/api/mem/read/<pid>` | POST | 读内存, body: `{address, size}` |
| `/api/mem/disasm/<pid>` | POST | 反汇编, body: `{address, count}` |
| `/api/mem/strings/<pid>` | POST | 字符串提取 |
| `/api/mem/svc_scan/<pid>` | POST | SVC #0 扫描 |
| `/api/mem/resolve/<pid>/<addr>` | GET | 地址→库解析 |
| `/api/mem/search/<pid>` | POST | 模式搜索 |
| `/api/mem/health` | GET | 健康检查 |

## kpmctl 命令参考

### detect_reverser 命令

```bash
dr_enable <pid>       # 启用并设置目标 PID
dr_needles            # ★ 查看捕获到的检测字符串
dr_status             # 查看状态统计
dr_dump <idx>         # 查看第 idx 条上下文 dump
dr_add_tid <tid>      # 添加特定 TID 监控
dr_config <key> <val> # 配置 (stack_scan/full_dump/all_threads on|off)
dr_clear              # 清除所有数据
```

### mem_monitor 命令

```bash
mem_mon_enable <pid>        # 启用
mem_mon_watch "string"      # 添加监控字符串
mem_mon_preset_frida        # 加载 Frida 检测预设 (13条)
mem_mon_preset_xjd          # 加载梆梆/数盾预设 (10条)
mem_mon_maps_filter on|off  # maps 内容过滤
mem_mon_status              # 状态
mem_mon_dump                # 导出日志
mem_mon_clear               # 清除
```

## 典型工作流

### 1. 逆向壳的检测目标 (最常用)

```bash
# Step 1: 启动目标 APP, 获取 PID
adb shell pidof com.example.app  # → 12345

# Step 2: 启用 detect_reverser
kpmctl svc_monitor dr_enable 12345

# Step 3: 等待壳执行检测 (通常启动后几秒内)

# Step 4: 查看捕获的 needle
kpmctl svc_monitor dr_needles

# 输出:
# [0] "frida"        hits=23  via=register(x1)  pc=0x7a00005678
# [1] "gum-js-loop"  hits=5   via=ptr_array(x2)
# [2] "gmain"        hits=8   via=register(x3)
# → 壳在检测这 3 个字符串!

# Step 5: 用 PC 地址在 IDA/Frida 中分析检测函数
# → 0x7a00005678 就是壳的检测入口
```

### 2. 完整的检测逻辑还原

```bash
# 同时启用两个模块
kpmctl svc_monitor dr_enable 12345
kpmctl svc_monitor mem_mon_enable 12345
kpmctl svc_monitor mem_mon_preset_frida

# 运行后:
kpmctl svc_monitor dr_needles     # 壳找什么 (needle)
kpmctl svc_monitor mem_mon_status  # 壳读什么 (haystack)
kpmctl svc_monitor mem_mon_dump    # 读取详情

# 结合分析:
# mem_monitor: maps 读了 156 次, "frida" 命中 15 次
# detect_reverser: x1 里拿着 "frida", PC=0x7a00005678
# → 在 0x7a00005678 处有一个自定义 memmem, 搜索 "frida"
```

## 文件清单

```
mem_analyzer/
├── mem_server.py                          # 独立启动器
├── app_integration_patch.py               # 集成到 app.py 的示例
├── README.md                              # 本文件
├── server/
│   └── mem_api.py                         # Flask API (含 dr_ 和 mem_ 端点)
├── static/
│   └── mem_analyzer.html                  # 前端 UI (8 tabs)
└── kpm/
    ├── detect_reverser.c                  # ★ 壳检测逆向 (抓 needle)
    ├── detect_reverser_integration.c      # 集成到 svc_monitor.c 指南
    ├── mem_monitor.c                      # 内存访问监控 (看 haystack)
    └── svc_monitor_integration.c          # mem_monitor 集成指南
```
