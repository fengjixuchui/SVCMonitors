# SVC Monitor PC Viewer — 逆向分析平台

## 架构

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐     ┌──────────────┐
│  KPM Module  │────▶│  Android APP │────▶│ PC Server  │────▶│ Web Browser  │
│  (Kernel)    │     │  (Bridge)    │     │ (Python)   │     │ (Dashboard)  │
│              │     │              │     │            │     │              │
│ JSONL events │     │ TCP Socket   │     │ Flask +    │     │ Vue3 + ECharts│
│ /data/svc/   │     │ port 9527    │     │ SocketIO   │     │ Timeline     │
└─────────────┘     └──────────────┘     └────────────┘     └──────────────┘
                     ADB Forward ──────────▶
                     tcp:9527 → tcp:9527
```

说明：
- Web UI 与 PC Server 之间使用 WebSocket（Socket.IO 强制 websocket transport），不做 HTTP 轮询拉取事件数据。
- Android APP 负责采集 KPM 事件并落库，同时可作为“事件服务端”通过 ADB forward 推送增量事件到 PC。

## 功能

- **实时事件流**: WebSocket 增量推送
- **全量搜索**: 搜索事件记录的任意字段（含 fp_chain / so 名等）
- **PID 分析**: 按进程聚合，展示进程时间线
- **事件详情**: 点击展开完整参数、栈回溯、VMA、耗时
- **syscall 统计**: 频率热力图、耗时分布
- **反调试检测**: 高亮 antidebug 事件
- **颜色标签**: 进程/网络/文件/环境四类 syscall 一眼分辨
- **线程对话式追踪**: 左侧 TID 列表勾选线程，右侧仅显示该线程执行流
- **Maps 查看**: Web 端直接查看 /proc/<pid>/maps
- **导出**: JSONL / CSV 一键导出
- **离线分析**: 拖拽 JSONL 文件直接导入

## 快速开始

### 方式一：App 服务端（推荐）

```bash
# 0. 安装依赖（必须包含 eventlet 才能 WebSocket-only）
pip install -r requirements.txt

# 1. 手机上打开 APP，开启“App 服务端”（默认端口 8080）
# 2. PC 一键启动（包含 adb forward + 启动 PC Viewer + 连接 App socket）
bash run_app_socket.sh 8080 0
```

启动后终端会打印 Web UI 地址，例如：

```
Web UI: http://localhost:5001
```

### 方式二：桥接模式（兼容）

```bash
# 使用 Android bridge 或其他采集方式，将事件导入到 PC Viewer（/api/ingest 或离线导入）
python server/app.py --port 5001
```

### 方式三：离线分析

```bash
# 1. 从设备拉取 JSONL 文件
adb pull /data/local/tmp/svc_events.jsonl ./

# 2. 直接加载离线文件
python server/app.py --no-bridge --load events.jsonl

# 或者在 Web 界面中拖拽上传
```

## 项目结构

```
svc_pc_viewer/
├── README.md
├── requirements.txt
├── server/
│   └── app.py              # Flask + SocketIO 后端
├── android_bridge/
│   ├── adb_bridge.py       # PC 端 ADB Bridge（推荐）
│   └── svc_bridge.sh       # 设备端 Shell Bridge
├── static/                  # 静态资源（如需要）
│   └── index.html
└── test_events.jsonl       # 测试数据
```
