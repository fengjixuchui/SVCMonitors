---
name: svc-monitor
description: >
  Android 内核 SVC 系统调用实时监控 CLI 工具。
  通过 adb + kpmctl 控制 KernelPatch KPM 模块，捕获目标进程所有系统调用。
  支持启停监控、按 NR/UID/TID 过滤、关注特定 SVC 类型、字段级深度分析、
  进程 maps 解析、线程行为检测。
  适用：反调试分析、风控指纹采集、加壳检测、算法还原。
---

# SVC Monitor CLI

## 快速开始

```bash
# 确保手机已连接 + svc_monitor.kpm 已加载
cd /path/to/KernelModules/SVCMonitor

# 查看状态
python3 svc.py status

# 一键监控会话
python3 svc.py session com.target.app --preset re_basic

# 操作目标 App 后，拉取事件
python3 svc.py drain --max 200 --stat

# 关注特定类型
python3 svc.py watch ptrace --limit 20
python3 svc.py watch mmap --tid 12345

# 深度分析
python3 svc.py analyze --search "/proc/self/maps"
python3 svc.py threads --max 500

# 地址解析
python3 svc.py maps 12345 --filter r-xp
python3 svc.py resolve 12345 0x7a3b4c5000 0x7a3b4c6000
```

## 全部命令

| 命令 | 说明 |
|------|------|
| `svc.py status` | 查看模块状态（enabled/UID/hooks/NRs） |
| `svc.py enable` / `disable` | 启停监控 |
| `svc.py set-uid <UID>` | 设置目标 UID |
| `svc.py preset <NAME>` | 加载预设（re_basic/re_full/file/net/proc/mem/security/anti_debug/fingerprint/proc_scan/crypto/binder） |
| `svc.py set-nrs <NR,NR,...>` | 自定义 NR 列表 |
| `svc.py drain [--max N] [--nr N] [--tid N] [--comm X] [--bt] [--stat]` | 拉取事件 |
| `svc.py watch <TYPE> [--max N] [--tid N] [--limit N]` | 关注特定 SVC 类型（ptrace/kill/mmap/mprotect/openat/read/write/clone/clone3/execve/connect/process_vm/prctl/seccomp/bpf/faccessat/all） |
| `svc.py analyze [--max N] [--nr N] [--tid N] [--comm X] [--search X] [--fields X]` | 字段级深度分析+可疑模式检测 |
| `svc.py threads [--max N]` | 按 TID 分组分析线程行为 |
| `svc.py maps <PID> [--filter X]` | 获取 /proc/PID/maps，标记可疑区域 |
| `svc.py resolve <PID> <ADDR...>` | hex 地址→模块名+偏移 |
| `svc.py get-uid <PKG>` | 包名→UID |
| `svc.py get-pid --package <PKG>` | UID→运行中 PID |
| `svc.py session <PKG|UID> [--preset X] [--nrs X] [--tier2]` | 一键配置+启用监控 |
| `svc.py clear` | 清空事件缓冲区 |
| `svc.py raw <CMD>` | 直接执行原始 ctl0 命令 |

## 典型工作流

### 反调试分析
```bash
python3 svc.py session com.target.app --preset re_full
# 操作 App，触发风控/检测
python3 svc.py watch ptrace --limit 30
python3 svc.py watch kill --limit 30
python3 svc.py analyze --search "/proc/self/maps"
python3 svc.py threads --max 500
# 看到可疑 TID → 解析 backtrace
python3 svc.py maps 12345 --filter r-xp     # 先看 maps
python3 svc.py resolve 12345 0x7a3b4c5000   # 解析地址
```

### 风控指纹
```bash
python3 svc.py session com.target.app --preset fingerprint --tier2
python3 svc.py analyze --nr 56 --search "/proc/" | grep -E "build|cpuinfo|status"
python3 svc.py analyze --search "ioctl" --fields desc
```

### 与 IDA/Frida 联动
```bash
# 1. 获取 backtrace 地址
python3 svc.py drain --max 200 --bt --nr 117
# 2. 解析地址到模块
python3 svc.py resolve <tgid> <addr1> <addr2>
# 3. 在 IDA 中跳转到 libXXX.so + 0xOFFSET
# 4. 用 Frida hook 该地址
```

## 可疑模式速查

| NR 组合 | 含义 | 严重度 |
|---------|------|--------|
| 56/63 + 129/131 | 检测线程（读进程信息+信号） | 🔴 HIGH |
| 117 | ptrace 跟踪/注入 | 🔴 HIGH |
| 222 + 271 | 跨进程内存注入 | 🔴 HIGH |
| 226 | mprotect 修改内存权限 | 🟠 MEDIUM |
| 277 | seccomp 安全策略 | 🟠 MEDIUM |
| 203/206 | 网络外联 | 🟡 LOW |
