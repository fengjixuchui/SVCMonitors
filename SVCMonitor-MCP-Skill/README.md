# SVC Monitor MCP Skill

## 这是什么

一个 MCP (Model Context Protocol) Server，让大模型可以通过 USB(adb) 连接手机，控制 KernelPatch Module 进行内核级 SVC 系统调用监控。

## 目录结构

```
svc_monitor_skill/
├── SKILL.md                 # Skill 描述文件（教大模型怎么用）
├── svc_monitor_mcp.py       # MCP Server 主程序（stdio transport）
├── svc_monitor_sse.py       # MCP Server SSE transport（HTTP方式）
├── svc_stream_client.py     # TCP 实时事件流客户端
├── svc_helpers.py           # 辅助工具（maps分析、地址解析、事件统计）
├── mcp_config.json          # Claude Desktop / Cursor 配置示例
├── requirements.txt         # Python 依赖
├── start.sh                 # 一键启动脚本
└── README.md                # 本文件
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 确认环境

```bash
# 检查 adb 连接、KPM 模块状态
bash start.sh check
```

### 3. 配置到你的 AI 客户端

**Claude Desktop / Cursor：**

把 `mcp_config.json` 的内容合并到你的 `claude_desktop_config.json` 中，修改 `cwd` 为实际路径：

```json
{
  "mcpServers": {
    "svc-monitor": {
      "command": "python3",
      "args": ["svc_monitor_mcp.py"],
      "cwd": "/你的实际路径/svc_monitor_skill"
    }
  }
}
```

说明：当前项目里的 MCP Server 已支持自动探测 APatch/KernelPatch 控制入口。对当前排查设备，实际可用入口是 `truncate <SuperKey> module ctl0 <module> '<cmd>'`，不是旧的 `/data/adb/ap/bin/kpatch` 固定路径。

**自定义 MCP Client：**

```bash
# stdio 模式（推荐，Claude Desktop 等使用）
bash start.sh stdio

# SSE 模式（HTTP方式，适合远程/多客户端）
bash start.sh sse 3001
```

## 提供的 Tools

| Tool | 功能 | 典型场景 |
|------|------|----------|
| `svc_status` | 查询监控状态 | 确认模块是否正常 |
| `svc_set_target` | 设置目标UID | 开始监控前 |
| `svc_enable` | 启停监控 | 控制采集 |
| `svc_set_nrs` | 设置监控的syscall号 | 按场景选择关注的调用 |
| `svc_drain` | 拉取事件 | 获取采集数据分析 |
| `svc_configure` | 配置采集参数 | 开启payload/backtrace |
| `svc_clear` | 清空缓冲区 | 重新开始采集 |
| `svc_get_maps` | 获取进程maps | 分析内存布局 |
| `svc_resolve_addr` | 地址→模块解析 | backtrace解析 |
| `svc_get_uid` | 包名→UID | 快速获取目标UID |
| `svc_analyze_threads` | 线程行为分析 | 自动识别检测线程 |
| `svc_monitor_session` | 一键启动会话 | 快速进入监控状态 |
| `svc_raw_command` | 原始kpatch命令 | 高级用法 |

## 与其他 Skill 联动

本 Skill 与你已有的 Frida/IDA/Unidbg Skill 形成完整工具链：

```
SVC Monitor (内核级全量采集)
    ↓ 发现关键调用点
Frida Skill (用户态精确hook/patch)
    ↓ 需要静态分析
IDA Skill (反汇编/反编译)
    ↓ 需要模拟验证
Unidbg Skill (离线模拟执行)
```

### 联动示例

1. **反调试分析**: SVC 发现 kill(self, SIGKILL) → 从 bt 获取地址 → IDA 分析该函数 → Frida patch
2. **指纹采集还原**: SVC 监控 openat+read → 发现读了哪些文件 → Unidbg 模拟该 SO 的 JNI 调用
3. **算法验证**: SVC 监控 mmap/mprotect → 发现动态解密段 → Frida dump → IDA 分析算法

## 注意事项

1. KPM 密钥 `XiaoLu0129` 在 `svc_monitor_mcp.py` 顶部，如果你改了需要同步修改
2. `enable_all` 事件量很大，生产环境建议精确设置 NR
3. 事件缓冲区有限（内核侧），及时 drain 避免溢出丢失
4. tier2 开启后性能开销增大，仅在需要 payload 时开启
