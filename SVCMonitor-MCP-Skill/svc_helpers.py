#!/usr/bin/env python3
"""
SVC Monitor 辅助工具集
提供地址解析、maps分析、事件统计等独立功能
"""

import subprocess
import json
import re
import sys
from typing import Optional


# ============ ADB 辅助 ============

def adb_shell(cmd: str, timeout: int = 10) -> str:
    """执行 adb shell 命令"""
    result = subprocess.run(
        ['adb', 'shell', cmd],
        capture_output=True, text=True, timeout=timeout
    )
    return result.stdout.strip()


def adb_root_shell(cmd: str, timeout: int = 10) -> str:
    """执行 adb shell su -c 命令"""
    result = subprocess.run(
        ['adb', 'shell', 'su', '-c', cmd],
        capture_output=True, text=True, timeout=timeout
    )
    return result.stdout.strip()


# ============ Maps 分析 ============

def parse_maps(pid: int) -> list[dict]:
    """解析 /proc/PID/maps"""
    output = adb_root_shell(f"cat /proc/{pid}/maps")
    mappings = []

    for line in output.strip().split('\n'):
        parts = line.split()
        if len(parts) < 5:
            continue

        addr_range = parts[0].split('-')
        start = int(addr_range[0], 16)
        end = int(addr_range[1], 16)
        perms = parts[1]
        offset = int(parts[2], 16)
        dev = parts[3]
        inode = parts[4]
        name = parts[5] if len(parts) > 5 else ""

        mappings.append({
            "start": start,
            "end": end,
            "size": end - start,
            "perms": perms,
            "offset": offset,
            "name": name,
            "line": line,
        })

    return mappings


def find_suspicious_regions(maps: list[dict]) -> list[dict]:
    """找出可疑的内存区域"""
    suspicious = []
    for m in maps:
        reasons = []
        if 'x' in m["perms"]:
            if not m["name"] or m["name"].startswith("["):
                reasons.append("匿名可执行段")
            if "memfd" in m["name"]:
                reasons.append("memfd创建的可执行段")
            if "xjd" in m["name"]:
                reasons.append("xjd-cache段")
            if "deleted" in m["name"]:
                reasons.append("已删除文件的映射")
            if m["name"] and not m["name"].startswith("/"):
                if "anon" in m["name"] or "jit" in m["name"].lower():
                    reasons.append("JIT/匿名代码段")

        if reasons:
            m["reasons"] = reasons
            suspicious.append(m)

    return suspicious


def resolve_address(addr: int, maps: list[dict]) -> Optional[dict]:
    """将地址解析到模块"""
    for m in maps:
        if m["start"] <= addr < m["end"]:
            return {
                "address": hex(addr),
                "module": m["name"] or "[anon]",
                "offset_in_file": hex(addr - m["start"] + m["offset"]),
                "offset_in_mapping": hex(addr - m["start"]),
                "perms": m["perms"],
                "mapping_range": f"{hex(m['start'])}-{hex(m['end'])}",
                "mapping_size": m["size"],
            }
    return None


# ============ 事件分析 ============

def analyze_events(events: list[dict]) -> dict:
    """对事件列表做统计分析"""
    analysis = {
        "total_events": len(events),
        "syscall_distribution": {},
        "thread_activity": {},
        "suspicious_patterns": [],
        "kill_events": [],
        "file_access": [],
    }

    for e in events:
        # syscall 分布
        nr = e.get("nr", -1)
        name = e.get("name", f"NR{nr}")
        analysis["syscall_distribution"][name] = analysis["syscall_distribution"].get(name, 0) + 1

        # 线程活动
        tid = e.get("pid", 0)
        comm = e.get("comm", "?")
        if tid not in analysis["thread_activity"]:
            analysis["thread_activity"][tid] = {"comm": comm, "count": 0, "nrs": set()}
        analysis["thread_activity"][tid]["count"] += 1
        analysis["thread_activity"][tid]["nrs"].add(nr)

        # kill 事件
        if nr in (129, 131):  # kill, tgkill
            analysis["kill_events"].append({
                "tid": tid,
                "comm": comm,
                "target": e.get("a0"),
                "signal": e.get("a1"),
                "bt": e.get("bt", []),
            })

        # 文件访问
        if nr == 56:  # openat
            path = e.get("payload_str", e.get("desc", ""))
            if path:
                analysis["file_access"].append({"tid": tid, "path": path})

    # 可疑模式检测（增强版）
    for tid, info in analysis["thread_activity"].items():
        nrs = info["nrs"]
        # 1. 检测线程: 读maps + kill/ptrace
        if (56 in nrs or 63 in nrs or 78 in nrs) and (129 in nrs or 131 in nrs or 117 in nrs):
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🔴 检测线程（读进程信息+信号/ptrace）",
                "severity": "HIGH"
            })
        # 2. ptrace 跟踪/注入
        if 117 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🟠 ptrace 跟踪/注入",
                "severity": "HIGH"
            })
        # 3. procfs 敏感读取: /proc/self/maps, /proc/self/mem, /proc/self/status
        if 56 in nrs or 63 in nrs or 48 in nrs:
            if any("proc/self" in str(e.get("desc", "")) or "proc/self" in str(e.get("payload_str", ""))
                   for e in events if e.get("pid") == tid):
                analysis["suspicious_patterns"].append({
                    "tid": tid, "comm": info["comm"],
                    "pattern": "🔴 敏感procfs读取 (/proc/self/maps, /proc/self/mem)",
                    "severity": "HIGH"
                })
        # 4. 内存注入: mmap+process_vm_writev
        if 222 in nrs and 271 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🔴 内存注入链 (mmap+process_vm_writev)",
                "severity": "HIGH"
            })
        # 5. mprotect 修改内存权限
        if 226 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🟠 修改内存权限 (mprotect)",
                "severity": "MEDIUM"
            })
        # 6. clone 创建线程
        if 220 in nrs or 435 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🟡 创建新线程/进程 (clone/clone3)",
                "severity": "LOW"
            })
        # 7. prctl 设置进程属性（可能设置 dumpable/no_new_privs）
        if 167 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🟡 prctl 进程属性修改 (可能 set dumpable/no_new_privs)",
                "severity": "LOW"
            })
        # 8. seccomp 安全策略
        if 277 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🟡 seccomp 安全策略操作",
                "severity": "MEDIUM"
            })
        # 9. connect + sendto 网络外联
        if 203 in nrs or 206 in nrs:
            analysis["suspicious_patterns"].append({
                "tid": tid, "comm": info["comm"],
                "pattern": "🟡 网络外联 (connect/sendto)",
                "severity": "MEDIUM"
            })

    # 转换 set 为 list（JSON序列化）
    for tid in analysis["thread_activity"]:
        analysis["thread_activity"][tid]["nrs"] = list(analysis["thread_activity"][tid]["nrs"])

    return analysis


# ============ Backtrace 增强 ============

def enrich_backtrace(bt_addrs: list[str], maps: list[dict]) -> list[dict]:
    """将 backtrace 地址列表解析为模块+偏移"""
    enriched = []
    for addr_str in bt_addrs:
        addr = int(addr_str, 16) if isinstance(addr_str, str) else addr_str
        resolved = resolve_address(addr, maps)
        if resolved:
            enriched.append(resolved)
        else:
            enriched.append({"address": hex(addr), "module": "[unmapped]"})
    return enriched


# ============ CLI ============

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  python svc_helpers.py maps <pid>          - 显示进程maps")
        print("  python svc_helpers.py suspicious <pid>    - 显示可疑区域")
        print("  python svc_helpers.py resolve <pid> <addr> - 解析地址")
        print("  python svc_helpers.py analyze <events.json> - 分析事件文件")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "maps":
        pid = int(sys.argv[2])
        maps = parse_maps(pid)
        for m in maps:
            print(m["line"])

    elif cmd == "suspicious":
        pid = int(sys.argv[2])
        maps = parse_maps(pid)
        suspicious = find_suspicious_regions(maps)
        if suspicious:
            print(f"⚠️ 发现 {len(suspicious)} 个可疑区域:\n")
            for s in suspicious:
                print(f"  {hex(s['start'])}-{hex(s['end'])} [{s['perms']}] {s['name']}")
                print(f"    原因: {', '.join(s['reasons'])}")
                print(f"    大小: {s['size']/1024:.1f} KB")
                print()
        else:
            print("✅ 未发现可疑区域")

    elif cmd == "resolve":
        pid = int(sys.argv[2])
        addr = int(sys.argv[3], 16)
        maps = parse_maps(pid)
        result = resolve_address(addr, maps)
        if result:
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ 地址 {hex(addr)} 未在任何映射中")

    elif cmd == "analyze":
        with open(sys.argv[2]) as f:
            events = json.load(f)
        analysis = analyze_events(events)
        print(json.dumps(analysis, indent=2, ensure_ascii=False))
