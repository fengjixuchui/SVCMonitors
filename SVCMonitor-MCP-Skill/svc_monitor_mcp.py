#!/usr/bin/env python3
"""
SVC Monitor MCP Server
通过 adb + kpatch 控制 KernelPatch Module，实现内核级 SVC 系统调用监控。
支持 stdio 和 sse 两种 transport。
"""

import asyncio
import json
import subprocess
import re
import os
from typing import Optional
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

# ============ 配置 ============

KPATCH_KEY = os.environ.get('KPATCH_KEY', 'XiaoLu0129')
MODULE_NAME = 'svc_monitor'
KPM_OUT_FILE = "/data/local/tmp/svc_out.json"
KPM_CTL0_CANDIDATES = [
    "/data/local/tmp/kpmctl {KEY} ctl0 {MODULE} '{CMD}'",
    "/data/adb/ap/bin/kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'",
    "/data/adb/kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'",
    "/data/adb/kpatch/bin/kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'",
    "kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'",
    "kpatch-android {KEY} kpm ctl0 {MODULE} '{CMD}'",
]
_resolved_ctl0_template: Optional[str] = None

# 预设方案（Python 侧本地映射，用 set_nrs 实现）
PRESETS = {
    "anti_debug": [117, 129, 131, 134, 167, 220, 435],
    "file_io": [56, 57, 62, 63, 64, 80],
    "memory": [214, 215, 222, 226],
    "network": [198, 200, 203, 206, 207],
    "process": [93, 94, 220, 221, 260, 435],
    "fingerprint": [29, 56, 63, 160, 167, 278],
    "proc_scan": [56, 63, 78, 79, 80, 222, 226, 117, 270, 271],
    "crypto_trace": [56, 29, 25, 63, 64, 215, 222, 226],
    "binder_watch": [29, 291, 198, 200, 202, 203, 206, 207],
}

# 特殊关注字段定义 — 聚焦检测行为的关键信号
WATCH_FIELDS = {
    "ptrace": {"nrs": [117], "fields": ["a0", "a1", "a2", "desc"], "label": "ptrace(request={a0}, pid={a1}, addr={a2})"},
    "kill": {"nrs": [129, 131], "fields": ["a0", "a1", "desc"], "label": "kill(pid={a0}, sig={a1})"},
    "mmap": {"nrs": [222], "fields": ["a0", "a1", "a2", "a3", "a4", "desc"], "label": "mmap(addr={a0}, len={a1}, prot={a2}, flags={a3}, fd={a4})"},
    "mprotect": {"nrs": [226], "fields": ["a0", "a1", "a2", "desc"], "label": "mprotect(addr={a0}, len={a1}, prot={a2})"},
    "openat": {"nrs": [56], "fields": ["a1", "desc"], "label": "openat(path={a1})"},
    "read": {"nrs": [63], "fields": ["a0", "a1", "ret", "desc"], "label": "read(fd={a0}, len={a1}) → {ret} bytes"},
    "write": {"nrs": [64], "fields": ["a0", "a1", "ret", "desc"], "label": "write(fd={a0}, len={a1}) → {ret} bytes"},
    "clone": {"nrs": [220], "fields": ["a0", "a1", "a2", "clone_fn", "desc"], "label": "clone(flags={a0}, stack={a1}) → fn={clone_fn}"},
    "clone3": {"nrs": [435], "fields": ["a0", "a1", "clone_fn", "desc"], "label": "clone3(args={a0}) → fn={clone_fn}"},
    "execve": {"nrs": [221], "fields": ["a0", "desc"], "label": "execve(path={a0})"},
    "connect": {"nrs": [203], "fields": ["a0", "a1", "a2", "desc"], "label": "connect(fd={a0}, addr={a1})"},
    "process_vm": {"nrs": [270, 271], "fields": ["a0", "a1", "a2", "a3", "desc"], "label": "proc_vm(pid={a0}, addr={a1}, len={a2})"},
    "prctl": {"nrs": [167], "fields": ["a0", "a1", "a2", "desc"], "label": "prctl(option={a0})"},
    "seccomp": {"nrs": [277], "fields": ["a0", "a1", "desc"], "label": "seccomp(op={a0}, flags={a1})"},
    "bpf": {"nrs": [280], "fields": ["a0", "a1", "a2", "desc"], "label": "bpf(cmd={a0})"},
    "faccessat": {"nrs": [48], "fields": ["a1", "a2", "desc"], "label": "faccessat(path={a1}, mode={a2})"},
}

# KPM 内核侧原生 preset 名（直接透传给 kpm ctl0）
KPM_NATIVE_PRESETS = {"re_basic", "re_full", "file", "net", "proc", "mem", "security", "all"}

# syscall 名称表 (ARM64 常用)
SYSCALL_NAMES = {
    0: "io_setup", 29: "ioctl", 48: "faccessat", 56: "openat", 57: "close",
    62: "lseek", 63: "read", 64: "write", 78: "readlinkat", 79: "fstatat",
    80: "fstat", 93: "exit", 94: "exit_group", 96: "set_tid_address",
    98: "futex", 117: "ptrace", 129: "kill", 131: "tgkill", 134: "rt_sigaction",
    135: "rt_sigprocmask", 160: "uname", 167: "prctl", 172: "getpid",
    173: "getppid", 174: "getuid", 175: "geteuid", 176: "getgid",
    178: "gettid", 198: "socket", 200: "bind", 203: "connect",
    206: "sendto", 207: "recvfrom", 214: "brk", 215: "munmap",
    220: "clone", 221: "execve", 222: "mmap", 226: "mprotect",
    233: "madvise", 260: "wait4", 278: "getrandom", 281: "execveat",
    435: "clone3",
}

# ============ ADB 工具函数 ============

def run_adb(cmd: str, timeout: int = 10) -> tuple[bool, str]:
    """执行 adb 命令，返回 (success, output)"""
    try:
        result = subprocess.run(
            ['adb', 'shell', 'su', '-c', cmd],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            err = result.stderr.strip()
            return False, err or output or "command failed"
        return True, output
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError:
        return False, "adb not found in PATH"
    except Exception as e:
        return False, str(e)


def read_kpm_out_file(timeout: int = 5) -> str:
    """读取模块写入的 ctl0 输出文件。某些 APatch 入口不会把结果直接输出到 stdout。"""
    ok, output = run_adb(f"cat {KPM_OUT_FILE} 2>/dev/null", timeout)
    return output.strip() if ok else ""


def looks_like_json(output: str) -> bool:
    stripped = output.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def build_ctl0_command(template: str, command: str) -> str:
    return (
        template
        .replace("{KEY}", KPATCH_KEY)
        .replace("{MODULE}", MODULE_NAME)
        .replace("{CMD}", command)
    )


def kpm_ctl(command: str, timeout: int = 15) -> tuple[bool, str]:
    """执行 KPM ctl0 命令，自动探测不同设备/APatch 版本的控制入口。"""
    global _resolved_ctl0_template

    candidates = []
    if _resolved_ctl0_template:
        candidates.append(_resolved_ctl0_template)
    for template in KPM_CTL0_CANDIDATES:
        if template not in candidates:
            candidates.append(template)

    last_error = "command failed"
    for template in candidates:
        # 避免读取到上一次遗留的输出文件
        run_adb(f"rm -f {KPM_OUT_FILE}", timeout=5)

        full_cmd = build_ctl0_command(template, command)
        ok, output = run_adb(full_cmd, timeout)
        output = output.strip()
        if not output:
            output = read_kpm_out_file()

        if ok and output:
            _resolved_ctl0_template = template
            return True, output
        if ok and not output:
            # 某些入口命令本身不输出，但如果连输出文件都没写，记录为可疑候选继续探测
            last_error = f"empty response via template: {template}"
            continue

        low = (output or "").lower()
        missing_cmd = (
            "not found" in low
            or "no such file" in low
            or "inaccessible or not found" in low
            or "permission denied" in low
        )
        if not missing_cmd:
            return False, output or last_error
        last_error = output or last_error

    return False, last_error


def parse_json_response(output: str) -> Optional[dict]:
    """尝试解析 JSON 响应"""
    try:
        # 有时候输出前面有非JSON内容，找到第一个 { 或 [
        start = output.find('{')
        if start == -1:
            start = output.find('[')
        if start == -1:
            return None
        return json.loads(output[start:])
    except json.JSONDecodeError:
        return None


def normalize_events(parsed) -> list[dict]:
    """将 kpm drain 返回的 JSON 统一转为事件列表"""
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        if "events" in parsed:
            return parsed["events"]
    return []


def get_syscall_name(nr: int) -> str:
    """返回 syscall 名称"""
    return SYSCALL_NAMES.get(nr, f"NR{nr}")


# ============ MCP Server ============

app = Server("svc-monitor")


@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="svc_status",
            description="查询 SVC Monitor 当前状态（是否启用、目标UID、已hook的syscall列表）",
            inputSchema={
                "type": "object",
                "properties": {},
            }
        ),
        Tool(
            name="svc_set_target",
            description="设置监控目标UID。先用 'adb shell pm list packages -U' 获取目标App的UID",
            inputSchema={
                "type": "object",
                "properties": {
                    "uid": {"type": "integer", "description": "目标App的UID（如10234）"},
                },
                "required": ["uid"]
            }
        ),
        Tool(
            name="svc_enable",
            description="启用/停止 SVC 监控",
            inputSchema={
                "type": "object",
                "properties": {
                    "enable": {"type": "boolean", "description": "true=启用, false=停止"},
                },
                "required": ["enable"]
            }
        ),
        Tool(
            name="svc_set_nrs",
            description="设置要监控的 syscall 号列表。可以用预设方案名或自定义号码列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "preset": {
                        "type": "string",
                        "description": "预设方案名。KPM原生: re_basic/re_full/file/net/proc/mem/security/all。便捷映射: anti_debug/file_io/memory/network/process/fingerprint",
                    },
                    "nrs": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "自定义 syscall 号列表（如 [56,63,64,129]）。如果指定了 preset 则忽略此参数"
                    },
                    "append": {
                        "type": "boolean",
                        "description": "true=追加到现有列表, false=替换（默认false）",
                        "default": False
                    }
                },
            }
        ),
        Tool(
            name="svc_drain",
            description="拉取已采集的 SVC 事件。返回JSON事件数组，包含syscall号/名称、PID/TID、参数、调用栈等",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_events": {
                        "type": "integer",
                        "description": "最多拉取事件数（默认200）",
                        "default": 200
                    },
                    "filter_nr": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "可选，只返回指定syscall号的事件"
                    },
                    "filter_tid": {
                        "type": "integer",
                        "description": "可选，只返回指定TID的事件"
                    },
                    "filter_comm": {
                        "type": "string",
                        "description": "可选，只返回指定进程名的事件（支持子串匹配）"
                    },
                },
            }
        ),
        Tool(
            name="svc_configure",
            description="配置监控参数（tier2数据采集、file_open路径采集、backtrace模式）",
            inputSchema={
                "type": "object",
                "properties": {
                    "tier2": {
                        "type": "boolean",
                        "description": "是否开启二级数据采集（read/write payload hexdump + 字符串提取）"
                    },
                    "filp_open": {
                        "type": "boolean",
                        "description": "是否开启 file open 路径采集"
                    },
                    "bt_mode": {
                        "type": "string",
                        "enum": ["accurate", "length"],
                        "description": "backtrace模式: accurate=精确回溯, length=仅栈深度"
                    },
                },
            }
        ),
        Tool(
            name="svc_clear",
            description="清空事件缓冲区",
            inputSchema={
                "type": "object",
                "properties": {},
            }
        ),
        Tool(
            name="svc_get_maps",
            description="获取目标进程的 /proc/PID/maps 内存映射信息。用于分析backtrace地址所在的模块",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "目标进程PID"},
                    "filter": {
                        "type": "string",
                        "description": "可选过滤关键词（如 'libexec' 或 'xjd-cache' 或 'r-xp'）"
                    },
                },
                "required": ["pid"]
            }
        ),
        Tool(
            name="svc_resolve_addr",
            description="将内存地址解析为 模块名+偏移。需要先获取maps信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "进程PID"},
                    "addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "要解析的地址列表（十六进制字符串，如 ['0x7a3b4c5000']）"
                    },
                },
                "required": ["pid", "addresses"]
            }
        ),
        Tool(
            name="svc_get_uid",
            description="获取指定包名的UID",
            inputSchema={
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "App包名（如 com.target.app）"},
                },
                "required": ["package"]
            }
        ),
        Tool(
            name="svc_get_pid",
            description="获取指定包名或UID对应的运行中进程PID。用于后续 maps 分析和地址解析",
            inputSchema={
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "App包名（如 com.target.app）"},
                    "uid": {"type": "integer", "description": "目标UID（如果不知道包名）"},
                },
            }
        ),
        Tool(
            name="svc_analyze_threads",
            description="分析已采集事件中的线程行为模式，识别检测线程、指纹采集线程等。注意：此操作会消耗事件缓冲区（drain），分析后事件不可再次读取",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_events": {
                        "type": "integer",
                        "description": "分析的事件数量上限（默认500）",
                        "default": 500
                    },
                },
            }
        ),
        Tool(
            name="svc_monitor_session",
            description="一键启动完整监控会话：设置UID + 加载预设 + 配置参数 + 启用监控",
            inputSchema={
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "目标App包名"
                    },
                    "uid": {
                        "type": "integer",
                        "description": "目标UID（如果不知道包名可以直接传UID）"
                    },
                    "preset": {
                        "type": "string",
                        "enum": ["anti_debug", "file_io", "memory", "network", "process", "fingerprint"],
                        "description": "预设方案"
                    },
                    "nrs": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "自定义syscall号列表"
                    },
                    "tier2": {
                        "type": "boolean",
                        "description": "是否开启payload采集",
                        "default": False
                    },
                    "bt_mode": {
                        "type": "string",
                        "enum": ["accurate", "length"],
                        "default": "accurate"
                    },
                },
            }
        ),
        Tool(
            name="svc_raw_command",
            description="直接执行 kpatch ctl0 原始命令（高级用户）",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的ctl0命令"},
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="svc_watch",
            description="关注特定 SVC 调用号的关键字段。自动提取 ptrace/kill/mmap/mprotect/openat/connect/clone/execve 等检测相关 syscall 的核心参数。适合快速扫描反调试、内存注入、进程间操作等行为",
            inputSchema={
                "type": "object",
                "properties": {
                    "watch_type": {
                        "type": "string",
                        "description": "关注类型。可选: ptrace, kill, mmap, mprotect, openat, read, write, clone, clone3, execve, connect, process_vm, prctl, seccomp, bpf, faccessat, all（全关注）",
                        "enum": ["ptrace", "kill", "mmap", "mprotect", "openat", "read", "write", "clone", "clone3", "execve", "connect", "process_vm", "prctl", "seccomp", "bpf", "faccessat", "all"]
                    },
                    "max_events": {
                        "type": "integer",
                        "description": "拉取事件上限（默认300）",
                        "default": 300
                    },
                    "filter_tid": {
                        "type": "integer",
                        "description": "可选，只分析指定TID的事件"
                    },
                },
                "required": ["watch_type"]
            }
        ),
        Tool(
            name="svc_analyze_fields",
            description="对事件进行字段级深度分析。支持按 NR、TID、COMM 过滤，提取指定字段（如 desc/a0-a5/pc/caller/fp/bt）进行模式识别。适合追踪特定进程的特定行为链",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter_nr": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "只分析这些 syscall 号"
                    },
                    "filter_tid": {
                        "type": "integer",
                        "description": "只分析这个 TID"
                    },
                    "filter_comm": {
                        "type": "string",
                        "description": "只分析匹配此进程名的事件"
                    },
                    "focus_fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "重点关注的字段列表，如 ['desc', 'a0', 'a1', 'pc', 'caller', 'fp', 'ret']。omit则返回全部字段摘要"
                    },
                    "max_events": {
                        "type": "integer",
                        "description": "分析事件数上限（默认200）",
                        "default": 200
                    },
                    "pattern_search": {
                        "type": "string",
                        "description": "在 desc 字段中搜索的关键词（如 '/proc/self/maps', 'frida', 'xposed', 'magisk', 'su'）"
                    },
                },
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict):

    if name == "svc_status":
        ok, output = kpm_ctl("status")
        if not ok:
            return [TextContent(type="text", text=f"❌ 获取状态失败: {output}")]
        parsed = parse_json_response(output)
        if parsed:
            # 美化输出
            enabled = parsed.get("enabled", False)
            uid = parsed.get("uid", "未设置")
            nrs = parsed.get("nrs", [])
            nr_names = [f"{nr}({SYSCALL_NAMES.get(nr, '?')})" for nr in nrs]
            result = f"状态: {'✅ 已启用' if enabled else '⏸️ 已停止'}\n"
            result += f"目标UID: {uid}\n"
            result += f"监控的syscall ({len(nrs)}个): {', '.join(nr_names)}\n"
            if "tier2" in parsed:
                result += f"Tier2(payload采集): {'开' if parsed['tier2'] else '关'}\n"
            if "bt_mode" in parsed:
                result += f"Backtrace模式: {parsed['bt_mode']}\n"
            result += f"\n原始响应:\n```json\n{json.dumps(parsed, indent=2)}\n```"
            return [TextContent(type="text", text=result)]
        return [TextContent(type="text", text=f"状态响应:\n{output}")]

    elif name == "svc_set_target":
        uid = arguments["uid"]
        ok, output = kpm_ctl(f"uid {uid}")
        if not ok:
            return [TextContent(type="text", text=f"❌ 设置UID失败: {output}")]
        return [TextContent(type="text", text=f"✅ 已设置监控目标 UID={uid}")]

    elif name == "svc_enable":
        enable = arguments["enable"]
        cmd = "enable" if enable else "disable"
        ok, output = kpm_ctl(cmd)
        if not ok:
            return [TextContent(type="text", text=f"❌ {cmd}失败: {output}")]
        return [TextContent(type="text", text=f"✅ 监控已{'启用' if enable else '停止'}")]

    elif name == "svc_set_nrs":
        preset = arguments.get("preset")
        nrs = arguments.get("nrs", [])
        append = arguments.get("append", False)

        if preset:
            # KPM 原生预设直接透传
            if preset in KPM_NATIVE_PRESETS:
                ok, output = kpm_ctl(f"preset {preset}")
                if not ok:
                    return [TextContent(type="text", text=f"❌ 加载预设失败: {output}")]
                return [TextContent(type="text", text=f"✅ 已加载KPM预设 '{preset}'")]
            # Python 侧本地映射
            elif preset in PRESETS:
                nrs = PRESETS[preset]
            else:
                return [TextContent(type="text", text=f"❌ 未知预设 '{preset}'，可选: {', '.join(list(PRESETS.keys()) + list(KPM_NATIVE_PRESETS))}")]

        if not nrs:
            return [TextContent(type="text", text="❌ 需要指定 preset 或 nrs")]

        if append:
            # 逐个 enable
            results = []
            for nr in nrs:
                ok, output = kpm_ctl(f"enable_nr {nr}")
                results.append(f"  NR {nr}({SYSCALL_NAMES.get(nr, '?')}): {'✅' if ok else '❌ ' + output}")
            return [TextContent(type="text", text="追加syscall结果:\n" + "\n".join(results))]
        else:
            nr_str = ",".join(str(n) for n in nrs)
            ok, output = kpm_ctl(f"set_nrs {nr_str}")
            if not ok:
                return [TextContent(type="text", text=f"❌ 设置NR失败: {output}")]
            nr_names = [f"{nr}({SYSCALL_NAMES.get(nr, '?')})" for nr in nrs]
            return [TextContent(type="text", text=f"✅ 已设置监控: {', '.join(nr_names)}")]

    elif name == "svc_drain":
        max_events = arguments.get("max_events", 200)
        filter_nr = arguments.get("filter_nr")
        filter_tid = arguments.get("filter_tid")
        filter_comm = arguments.get("filter_comm")

        ok, output = kpm_ctl(f"drain {max_events}", timeout=30)
        if not ok:
            return [TextContent(type="text", text=f"❌ 拉取事件失败: {output}")]

        parsed = parse_json_response(output)
        if not parsed:
            return [TextContent(type="text", text=f"事件数据（原始）:\n{output[:5000]}")]

        events = parsed if isinstance(parsed, list) else parsed.get("events", [])

        # 应用过滤
        if filter_nr:
            events = [e for e in events if e.get("nr") in filter_nr]
        if filter_tid:
            events = [e for e in events if e.get("pid") == filter_tid]
        if filter_comm:
            events = [e for e in events if filter_comm.lower() in e.get("comm", "").lower()]

        # 格式化输出
        if not events:
            return [TextContent(type="text", text="📭 无事件（缓冲区为空或过滤后无匹配）")]

        result = f"📊 获取到 {len(events)} 个事件:\n\n"

        # 统计摘要
        nr_counter = {}
        tid_counter = {}
        for e in events:
            nr = e.get("nr", -1)
            nr_counter[nr] = nr_counter.get(nr, 0) + 1
            tid = e.get("pid", 0)  # KPM中pid字段实际是tid
            tid_counter[tid] = tid_counter.get(tid, 0) + 1

        result += "**Syscall 分布:**\n"
        for nr, count in sorted(nr_counter.items(), key=lambda x: -x[1]):
            result += f"  {SYSCALL_NAMES.get(nr, f'NR{nr}')}({nr}): {count}次\n"

        result += f"\n**活跃线程 ({len(tid_counter)}个):**\n"
        for tid, count in sorted(tid_counter.items(), key=lambda x: -x[1])[:10]:
            comm = next((e.get("comm", "?") for e in events if e.get("pid") == tid), "?")
            result += f"  TID {tid} [{comm}]: {count}次\n"

        result += f"\n**事件详情 (前50条):**\n```json\n"
        result += json.dumps(events[:50], indent=2, ensure_ascii=False)
        result += "\n```"

        return [TextContent(type="text", text=result)]

    elif name == "svc_configure":
        results = []

        if "tier2" in arguments:
            val = "on" if arguments["tier2"] else "off"
            ok, output = kpm_ctl(f"tier2 {val}")
            results.append(f"Tier2: {'✅ 开' if arguments['tier2'] else '⏸️ 关'} {'✅' if ok else '❌ ' + output}")

        if "filp_open" in arguments:
            val = "on" if arguments["filp_open"] else "off"
            ok, output = kpm_ctl(f"filp_open {val}")
            results.append(f"FilpOpen: {'✅ 开' if arguments['filp_open'] else '⏸️ 关'} {'✅' if ok else '❌ ' + output}")

        if "bt_mode" in arguments:
            ok, output = kpm_ctl(f"bt_mode {arguments['bt_mode']}")
            results.append(f"BT模式: {arguments['bt_mode']} {'✅' if ok else '❌ ' + output}")

        if not results:
            return [TextContent(type="text", text="❌ 未指定任何配置参数")]

        return [TextContent(type="text", text="配置结果:\n" + "\n".join(results))]

    elif name == "svc_clear":
        ok, output = kpm_ctl("clear")
        if not ok:
            return [TextContent(type="text", text=f"❌ 清空失败: {output}")]
        return [TextContent(type="text", text="✅ 事件缓冲区已清空")]

    elif name == "svc_get_maps":
        pid = arguments["pid"]
        filter_kw = arguments.get("filter")

        ok, output = run_adb(f"cat /proc/{pid}/maps", timeout=10)
        if not ok:
            return [TextContent(type="text", text=f"❌ 读取maps失败: {output}")]

        lines = output.strip().split('\n')

        if filter_kw:
            lines = [l for l in lines if filter_kw.lower() in l.lower()]

        # 标记可疑区域
        result = f"📋 /proc/{pid}/maps ({len(lines)} entries):\n\n"
        suspicious = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                perms = parts[1]
                name = parts[-1] if len(parts) >= 6 else "[anon]"
                # 可疑: 匿名可执行段、非标准库的可执行段
                if 'x' in perms and ('[anon' in name or 'memfd' in name or 'xjd' in name or 'deleted' in name):
                    suspicious.append(line)

        if suspicious:
            result += "⚠️ **可疑区域:**\n```\n"
            result += "\n".join(suspicious)
            result += "\n```\n\n"

        result += "**完整maps:**\n```\n"
        result += "\n".join(lines[:200])  # 限制输出
        if len(lines) > 200:
            result += f"\n... (共{len(lines)}行，已截断)"
        result += "\n```"

        return [TextContent(type="text", text=result)]

    elif name == "svc_resolve_addr":
        pid = arguments["pid"]
        addresses = arguments["addresses"]

        # 获取 maps
        ok, output = run_adb(f"cat /proc/{pid}/maps", timeout=10)
        if not ok:
            return [TextContent(type="text", text=f"❌ 读取maps失败: {output}")]

        # 解析 maps
        mappings = []
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 5:
                addr_range = parts[0].split('-')
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
                perms = parts[1]
                offset = int(parts[2], 16)
                name = parts[-1] if len(parts) >= 6 else "[anon]"
                mappings.append((start, end, perms, offset, name))

        # 解析地址
        results = []
        for addr_str in addresses:
            addr = int(addr_str, 16) if isinstance(addr_str, str) else addr_str
            resolved = None
            for start, end, perms, offset, name in mappings:
                if start <= addr < end:
                    file_offset = addr - start + offset
                    resolved = {
                        "address": hex(addr),
                        "module": name,
                        "offset": hex(file_offset),
                        "relative": hex(addr - start),
                        "perms": perms,
                        "range": f"{hex(start)}-{hex(end)}"
                    }
                    break
            if not resolved:
                resolved = {"address": hex(addr), "module": "[unmapped]", "offset": "?"}
            results.append(resolved)

        result = "🔍 地址解析结果:\n\n"
        for r in results:
            result += f"  {r['address']} → **{r['module']}** + {r.get('offset', '?')}"
            if r.get('perms'):
                result += f" [{r['perms']}]"
            result += "\n"

        result += f"\n```json\n{json.dumps(results, indent=2)}\n```"
        return [TextContent(type="text", text=result)]

    elif name == "svc_get_uid":
        package = arguments["package"]
        ok, output = run_adb(f"pm list packages -U 2>/dev/null | grep {package}", timeout=10)
        if not ok or not output:
            # 备选方案
            ok, output = run_adb(f"dumpsys package {package} | grep userId", timeout=10)
            if not ok:
                return [TextContent(type="text", text=f"❌ 获取UID失败: {output}")]

        # 解析UID
        uid_match = re.search(r'uid[=:](\d+)', output)
        if uid_match:
            uid = int(uid_match.group(1))
            return [TextContent(type="text", text=f"✅ {package} → UID={uid}")]

        return [TextContent(type="text", text=f"解析结果:\n{output}")]

    elif name == "svc_get_pid":
        package = arguments.get("package")
        uid = arguments.get("uid")

        if package:
            # 通过包名查找进程PID
            ok, output = run_adb(f"pidof {package}", timeout=5)
            if ok and output.strip():
                pids = output.strip().split()
                return [TextContent(type="text", text=f"✅ {package} → PID={', '.join(pids)}（主进程={pids[0]}）")]
            # 备选：通过 ps 查找
            ok, output = run_adb(f"ps -A | grep {package}", timeout=10)
            if ok and output:
                lines = [l for l in output.strip().split('\n') if package in l]
                if lines:
                    result = f"进程列表:\n"
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 9:
                            result += f"  PID={parts[1]} PPID={parts[2]} [{parts[-1]}]\n"
                    return [TextContent(type="text", text=result)]
            return [TextContent(type="text", text=f"❌ 未找到 {package} 的运行进程（App可能未启动）")]

        elif uid:
            # 通过UID查找进程
            ok, output = run_adb(f"ps -A -o PID,UID,NAME | grep {uid}", timeout=10)
            if ok and output:
                return [TextContent(type="text", text=f"UID {uid} 的进程:\n{output}")]
            return [TextContent(type="text", text=f"❌ 未找到 UID={uid} 的运行进程")]

        return [TextContent(type="text", text="❌ 需要指定 package 或 uid")]

    elif name == "svc_analyze_threads":
        max_events = arguments.get("max_events", 500)

        ok, output = kpm_ctl(f"drain {max_events}", timeout=30)
        if not ok:
            return [TextContent(type="text", text=f"❌ 拉取事件失败: {output}")]

        parsed = parse_json_response(output)
        if not parsed:
            return [TextContent(type="text", text="❌ 无法解析事件数据")]

        events = parsed if isinstance(parsed, list) else parsed.get("events", [])
        if not events:
            return [TextContent(type="text", text="📭 无事件可分析")]

        # 按TID分组分析
        thread_events = {}
        for e in events:
            tid = e.get("pid", 0)
            if tid not in thread_events:
                thread_events[tid] = {"comm": e.get("comm", "?"), "events": []}
            thread_events[tid]["events"].append(e)

        result = f"🧬 线程行为分析 ({len(events)}个事件, {len(thread_events)}个线程):\n\n"

        for tid, info in sorted(thread_events.items(), key=lambda x: -len(x[1]["events"])):
            evts = info["events"]
            comm = info["comm"]
            nr_seq = [e.get("nr") for e in evts]
            nr_set = set(nr_seq)

            # 行为模式判断
            patterns = []
            if 129 in nr_set or 131 in nr_set:
                patterns.append("🚨 发起kill/tgkill")
            if 117 in nr_set:
                patterns.append("🔍 ptrace操作")
            if 220 in nr_set or 435 in nr_set:
                patterns.append("🧵 创建子线程")
            if 56 in nr_set and 63 in nr_set:
                # 检查是否读 /proc/
                has_proc = any("proc" in str(e.get("payload_str", "")) for e in evts)
                if has_proc:
                    patterns.append("📁 读取/proc/信息")
                else:
                    patterns.append("📁 文件I/O")
            if 222 in nr_set or 226 in nr_set:
                patterns.append("💾 内存映射/保护修改")
            if 167 in nr_set:
                patterns.append("⚙️ prctl操作")

            # 判断是否为检测线程
            is_detector = (129 in nr_set or 131 in nr_set) and (56 in nr_set or 117 in nr_set)

            result += f"### TID {tid} [{comm}] - {len(evts)}个事件"
            if is_detector:
                result += " ⚠️ **疑似检测线程**"
            result += "\n"
            result += f"  Syscall序列: {' → '.join(SYSCALL_NAMES.get(nr, str(nr)) for nr in nr_seq[:20])}"
            if len(nr_seq) > 20:
                result += "..."
            result += "\n"
            if patterns:
                result += f"  行为特征: {', '.join(patterns)}\n"
            result += "\n"

        return [TextContent(type="text", text=result)]

    elif name == "svc_monitor_session":
        package = arguments.get("package")
        uid = arguments.get("uid")
        preset = arguments.get("preset")
        nrs = arguments.get("nrs")
        tier2 = arguments.get("tier2", False)
        bt_mode = arguments.get("bt_mode", "accurate")

        steps = []

        # Step 1: 获取UID
        if package and not uid:
            ok, output = run_adb(f"dumpsys package {package} | grep userId", timeout=10)
            uid_match = re.search(r'userId=(\d+)', output) if ok else None
            if uid_match:
                uid = int(uid_match.group(1))
                steps.append(f"✅ {package} → UID={uid}")
            else:
                return [TextContent(type="text", text=f"❌ 无法获取 {package} 的UID")]

        if not uid:
            return [TextContent(type="text", text="❌ 需要指定 package 或 uid")]

        # Step 2: 设置UID
        ok, _ = kpm_ctl(f"uid {uid}")
        steps.append(f"{'✅' if ok else '❌'} 设置 UID={uid}")

        # Step 3: 设置NR
        if preset:
            ok, _ = kpm_ctl(f"preset {preset}")
            steps.append(f"{'✅' if ok else '❌'} 加载预设 '{preset}'")
        elif nrs:
            nr_str = ",".join(str(n) for n in nrs)
            ok, _ = kpm_ctl(f"set_nrs {nr_str}")
            steps.append(f"{'✅' if ok else '❌'} 设置NR: {nr_str}")

        # Step 4: 配置
        if tier2:
            ok, _ = kpm_ctl("tier2 on")
            steps.append(f"{'✅' if ok else '❌'} Tier2 ON")

        ok, _ = kpm_ctl(f"bt_mode {bt_mode}")
        steps.append(f"{'✅' if ok else '❌'} BT模式: {bt_mode}")

        # Step 5: 清空旧事件并启用
        kpm_ctl("clear")
        ok, _ = kpm_ctl("enable")
        steps.append(f"{'✅' if ok else '❌'} 监控已启用")

        result = "🚀 **监控会话已启动**\n\n"
        result += "\n".join(steps)
        result += "\n\n💡 下一步: 操作目标App，然后用 `svc_drain` 拉取事件"

        return [TextContent(type="text", text=result)]

    elif name == "svc_watch":
        watch_type = arguments["watch_type"]
        max_events = arguments.get("max_events", 300)
        filter_tid = arguments.get("filter_tid")

        # 确定要关注的 NR
        if watch_type == "all":
            watch_nrs = [nr for nrs_list in [v["nrs"] for v in WATCH_FIELDS.values()] for nr in nrs_list]
        else:
            watch_nrs = WATCH_FIELDS[watch_type]["nrs"]

        # 拉取事件
        ok, output = kpm_ctl(f"drain {max_events}")
        if not ok:
            return [TextContent(type="text", text=f"❌ 拉取事件失败: {output}")]

        parsed = parse_json_response(output)
        if not parsed:
            return [TextContent(type="text", text="❌ 解析事件失败")]

        events = normalize_events(parsed)

        # 过滤
        matched = [e for e in events if e.get("nr") in watch_nrs]
        if filter_tid is not None:
            matched = [e for e in matched if e.get("pid") == filter_tid]

        # 提取关键字段
        lines = [f"## 🔍 svc_watch: {watch_type} — 匹配 {len(matched)}/{len(events)} 事件\n"]
        config = WATCH_FIELDS[watch_type]
        for e in matched[:80]:
            fields = {k: e.get(k) for k in config["fields"]}
            label = config["label"].format(**e)
            meta = f"TID={e.get('pid', '?')} {e.get('comm', '?')} pc={e.get('pc','?')}"
            lines.append(f"**{label}**  _{meta}_")
            for k, v in fields.items():
                if k != "desc":
                    lines.append(f"  - `{k}` = {v}")
            if "desc" in fields and fields["desc"]:
                lines.append(f"  - desc: `{fields['desc']}`")
            lines.append("")

        return [TextContent(type="text", text="\n".join(lines[:200]))]

    elif name == "svc_analyze_fields":
        max_events = arguments.get("max_events", 200)
        filter_nr = arguments.get("filter_nr")
        filter_tid = arguments.get("filter_tid")
        filter_comm = arguments.get("filter_comm")
        focus_fields = arguments.get("focus_fields")
        pattern = arguments.get("pattern_search", "")

        ok, output = kpm_ctl(f"drain {max_events}")
        if not ok:
            return [TextContent(type="text", text=f"❌ 拉取事件失败: {output}")]

        parsed = parse_json_response(output)
        if not parsed:
            return [TextContent(type="text", text="❌ 解析事件失败")]

        events = normalize_events(parsed)
        if filter_nr:
            events = [e for e in events if e.get("nr") in filter_nr]
        if filter_tid is not None:
            events = [e for e in events if e.get("pid") == filter_tid]
        if filter_comm:
            comm = filter_comm.lower()
            events = [e for e in events if comm in (e.get("comm", "") or "").lower()]
        if pattern:
            events = [e for e in events if pattern.lower() in (e.get("desc", "") or "").lower()]

        # 统计摘要
        from collections import Counter
        nr_dist = Counter(e.get("nr") for e in events)
        tid_dist = Counter(e.get("pid") for e in events)

        lines = [f"## 📊 字段级分析 — 匹配 {len(events)} 事件\n"]
        lines.append("### Syscall 分布")
        for nr, cnt in nr_dist.most_common(15):
            lines.append(f"  - {get_syscall_name(nr)}({nr}): {cnt}")

        lines.append(f"\n### 活跃线程 (Top 10)")
        for tid, cnt in tid_dist.most_common(10):
            comm = next((e.get("comm", "?") for e in events if e.get("pid") == tid), "?")
            lines.append(f"  - TID={tid} [{comm}]: {cnt} events")

        # 字段摘要
        if focus_fields:
            lines.append(f"\n### 关注字段: {', '.join(focus_fields)}\n")
            for e in events[:40]:
                header = f"**{get_syscall_name(e.get('nr'))}({e.get('nr')})** TID={e.get('pid')} comm={e.get('comm')}"
                vals = []
                for f in focus_fields:
                    v = e.get(f)
                    if v is not None:
                        if len(str(v)) < 128:
                            vals.append(f"`{f}`={v}")
                        else:
                            vals.append(f"`{f}`={str(v)[:100]}…")
                lines.append(f"{header}  " + "  ".join(vals))

        return [TextContent(type="text", text="\n".join(lines[:150]))]

    elif name == "svc_raw_command":
        command = arguments["command"]
        ok, output = kpm_ctl(command)
        status = "✅" if ok else "❌"
        return [TextContent(type="text", text=f"{status} 命令: {command}\n响应:\n{output}")]

    else:
        return [TextContent(type="text", text=f"❌ 未知工具: {name}")]


# ============ 入口 ============

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
