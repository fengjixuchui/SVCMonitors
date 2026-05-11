#!/usr/bin/env python3
"""
SVCMonitor CLI — Android 内核 SVC 监控命令行工具

通过 adb + kpmctl 控制 KernelPatch KPM 模块，实现 syscall 级别监控与分析。

用法:
  svc.py status                    查看模块状态
  svc.py enable / disable          启停监控
  svc.py set-uid <UID>             设置目标 UID
  svc.py preset <NAME>             加载预设方案
  svc.py set-nrs <NR,NR,...>       自定义 NR 列表
  svc.py drain [选项]              拉取事件
  svc.py watch <类型> [选项]        关注特定 SVC 关键字段
  svc.py analyze [选项]             字段级深度分析
  svc.py threads [选项]             线程行为分析
  svc.py maps <PID>                进程内存映射
  svc.py resolve <PID> <地址>      地址→模块解析
  svc.py get-uid <包名>            包名→UID
  svc.py get-pid <包名|UID>        获取运行中 PID
  svc.py session <包名|UID> [选项]  一键监控会话
  svc.py clear                     清空事件缓冲
  svc.py raw <命令>                执行原始 ctl0 命令

依赖: Python 3.8+, adb, 已加载 svc_monitor.kpm, 设备已连接

配置: 环境变量 KPATCH_KEY (默认 XiaoLu0129)
"""

import subprocess, json, sys, os, re, argparse, textwrap
from collections import Counter

# ═══════════ 配色 ═══════════
C = {"R": "\033[31m", "G": "\033[32m", "Y": "\033[33m", "B": "\033[34m",
     "M": "\033[35m", "C": "\033[36m", "W": "\033[0m", "D": "\033[2m"}

# ═══════════ 配置 ═══════════
KEY = os.environ.get("KPATCH_KEY", "XiaoLu0129")
MODULE = "svc_monitor"
CTL0_CANDIDATES = [
    '/data/local/tmp/kpmctl {KEY} ctl0 {MODULE} "{CMD}"',
    '/data/adb/ap/bin/kpatch {KEY} kpm ctl0 {MODULE} "{CMD}"',
    '/data/adb/kpatch {KEY} kpm ctl0 {MODULE} "{CMD}"',
    'kpatch {KEY} kpm ctl0 {MODULE} "{CMD}"',
    'kpatch-android {KEY} kpm ctl0 {MODULE} "{CMD}"',
]
_resolved = None

# ═══════════ 预设 ═══════════
PRESETS = {
    "re_basic":  [56,48,78,221,222,226,198,203,117,167,29,134,279,280],
    "re_full":   [56,48,35,78,79,63,64,221,281,220,435,93,94,222,226,215,232,198,200,203,206,207,117,167,29,25,129,131,134,135,277,280,279,146,144,147,105,273,97,268,261,291],
    "file":      [56,57,48,35,78,79,80,61,63,64,62,34,38,276,53,54,291,43,27,5,8],
    "net":       [198,200,201,202,203,206,207,208,209,210,211,212,242],
    "proc":      [221,281,220,435,93,94,95,260,117,129,130,131,270,271],
    "mem":       [222,226,215,214,232,233,279,270,271],
    "security":  [117,277,280,146,144,147,149,105,273,106,97,268,91,167,134],
    "anti_debug":[117,129,131,134,167,220,435],
    "fingerprint":[29,56,63,160,167,278],
    "proc_scan": [56,63,78,79,80,222,226,117,270,271],
    "crypto":    [56,29,25,63,64,215,222,226],
    "binder":    [29,291,198,200,202,203,206,207],
}

WATCH_TYPES = {
    "ptrace":     {"nrs":[117], "label":"ptrace(req={a0}, pid={a1}, addr={a2})"},
    "kill":       {"nrs":[129,131], "label":"kill/tgkill(pid={a0}, sig={a1})"},
    "mmap":       {"nrs":[222], "label":"mmap(addr={a0}, len={a1}, prot={a2}, flags={a3}, fd={a4})"},
    "mprotect":   {"nrs":[226], "label":"mprotect(addr={a0}, len={a1}, prot={a2})"},
    "openat":     {"nrs":[56], "label":"openat(path_desc={a1})"},
    "read":       {"nrs":[63], "label":"read(fd={a0}, len={a1})→{ret}"},
    "write":      {"nrs":[64], "label":"write(fd={a0}, len={a1})→{ret}"},
    "clone":      {"nrs":[220], "label":"clone(flags={a0}, fn={clone_fn})"},
    "clone3":     {"nrs":[435], "label":"clone3(args={a0}, fn={clone_fn})"},
    "execve":     {"nrs":[221], "label":"execve(path={a0})"},
    "connect":    {"nrs":[203], "label":"connect(fd={a0}, addr={a1})"},
    "process_vm": {"nrs":[270,271], "label":"proc_vm(pid={a0}, addr={a1}, len={a2})"},
    "prctl":      {"nrs":[167], "label":"prctl(opt={a0})"},
    "seccomp":    {"nrs":[277], "label":"seccomp(op={a0}, flags={a1})"},
    "bpf":        {"nrs":[280], "label":"bpf(cmd={a0})"},
    "faccessat":  {"nrs":[48], "label":"faccessat(path={a1}, mode={a2})"},
}

SYSCALL_NAMES = {
    0:"io_setup",29:"ioctl",48:"faccessat",56:"openat",57:"close",62:"lseek",
    63:"read",64:"write",78:"readlinkat",79:"fstatat",80:"fstat",93:"exit",
    94:"exit_group",96:"set_tid_address",97:"unshare",98:"futex",105:"init_module",
    106:"delete_module",117:"ptrace",129:"kill",130:"tkill",131:"tgkill",
    134:"rt_sigaction",135:"rt_sigprocmask",144:"setgid",146:"setuid",
    147:"setresuid",160:"gettimeofday",167:"prctl",172:"getpid",198:"socket",
    200:"bind",201:"listen",202:"accept",203:"connect",206:"sendto",
    207:"recvfrom",214:"brk",215:"munmap",220:"clone",221:"execve",222:"mmap",
    226:"mprotect",232:"mincore",233:"madvise",260:"wait4",261:"prlimit64",
    268:"setns",270:"process_vm_readv",271:"process_vm_writev",
    273:"finit_module",277:"seccomp",278:"getrandom",279:"memfd_create",
    280:"bpf",281:"execveat",291:"statx",435:"clone3",
}


# ═══════════ ADB 通信 ═══════════

def adb_sh(cmd: str, timeout: int = 15) -> tuple[bool, str]:
    """执行 adb shell <cmd> (无需 root)"""
    try:
        r = subprocess.run(
            ["adb", "shell", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace"
        )
        out = r.stdout.strip()
        if r.returncode != 0:
            err = r.stderr.strip()
            if err:
                out = f"{out}\n{err}".strip()
            return False, out
        return True, out
    except subprocess.TimeoutExpired:
        return False, "超时"
    except FileNotFoundError:
        return False, "adb 未安装或不在 PATH 中"


def adb_su(cmd: str, timeout: int = 15) -> tuple[bool, str]:
    """执行 adb shell su -c <cmd> (需要 root)"""
    try:
        r = subprocess.run(
            ["adb", "shell", "su", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace"
        )
        out = r.stdout.strip()
        if r.returncode != 0:
            err = r.stderr.strip()
            if err:
                out = f"{out}\n{err}".strip()
            return False, out
        return True, out
    except subprocess.TimeoutExpired:
        return False, "超时"
    except FileNotFoundError:
        return False, "adb 未安装或不在 PATH 中"


def kpm_ctl(command: str, timeout: int = 15) -> tuple[bool, any]:
    """向 KPM 发送 ctl0 命令，返回 (ok, parsed_json|error_string)"""
    global _resolved

    order = [_resolved] if _resolved else []
    for t in CTL0_CANDIDATES:
        if t not in order:
            order.append(t)

    for template in order:
        cmd = template.replace("{KEY}", KEY).replace("{MODULE}", MODULE).replace("{CMD}", command)
        ok, out = adb_sh(cmd, timeout)
        if not ok and not out:
            continue

        # try parsing JSON
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    data = json.loads(line)
                    if isinstance(data, dict) and data.get("ok"):
                        _resolved = template
                        return True, data
                    if isinstance(data, list):
                        _resolved = template
                        return True, data
                except json.JSONDecodeError:
                    pass

        # check for known error patterns
        low = out.lower()
        if "not found" in low or "no such file" in low:
            continue
        if "permission denied" in low:
            return False, out
        # unknown response from this template - it might be the right path but bad command
        if out:
            return False, out

    return False, "无法连接到 KPM 模块（请确认手机已连接、svc_monitor 已加载）"


def kpm_drain(max_events: int = 500):
    """拉取事件并返回列表"""
    ok, resp = kpm_ctl(f"drain {max_events}")
    if not ok:
        print(f"{C['R']}✗ 拉取失败: {resp}{C['W']}", file=sys.stderr)
        return []
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict) and "events" in resp:
        return resp["events"]
    return []


def get_syscall_name(nr: int) -> str:
    return SYSCALL_NAMES.get(nr, f"NR{nr}")


# ═══════════ 格式化输出 ═══════════

def fmt_event(e: dict, show_bt: bool = False) -> str:
    """格式化单个事件"""
    nr = e.get("nr", 0)
    name = e.get("name") or get_syscall_name(nr)
    pid = e.get("pid", "?")
    tgid = e.get("tgid", "?")
    comm = e.get("comm", "?")
    desc = e.get("desc", "")
    ret = e.get("ret", "")
    pc = e.get("pc", "")

    parts = [
        f"{C['B']}{name}({nr}){C['W']}",
        f"{C['D']}TID={pid} TGID={tgid}{C['W']}",
        f"{C['M']}{comm}{C['W']}",
    ]
    if pc:
        try:
            pc_hex = hex(int(pc)) if isinstance(pc, str) else hex(pc)
        except Exception:
            pc_hex = str(pc)
        parts.append(f"{C['D']}pc={pc_hex}{C['W']}")
    if ret is not None and ret != "":
        parts.append(f"{C['D']}ret={ret}{C['W']}")
    if desc:
        parts.append(f"{C['G']}{desc[:120]}{C['W']}")
    if show_bt:
        bt = e.get("bt", [])
        if bt:
            bt_str = " ← ".join(str(a) for a in bt[:5])
            parts.append(f"{C['Y']}bt: [{bt_str}]{C['W']}")
    return " | ".join(parts)


# ═══════════ 子命令实现 ═══════════

def cmd_status():
    """查看模块状态"""
    ok, resp = kpm_ctl("status")
    if not ok:
        print(f"{C['R']}✗ {resp}{C['W']}")
        return 1
    print(f"{C['B']}═══ SVC Monitor 状态 ═══{C['W']}")
    print(f"  启用: {C['G'] if resp.get('enabled') else C['R']}{resp.get('enabled')}{C['W']}")
    print(f"  版本: {resp.get('version', '?')}")
    print(f"  目标 UID: {resp.get('target_uid', -1)}")
    print(f"  已安装 Hook: {resp.get('hooks_installed', 0)}")
    print(f"  正在记录 NR: {resp.get('nrs_logging', 0)}")
    print(f"  事件总数: {resp.get('events_total', 0)}")
    print(f"  缓冲中: {resp.get('events_buffered', 0)} | 丢弃: {resp.get('events_dropped', 0)}")
    print(f"  Tier2: {resp.get('tier2', False)} | bt_mode: {resp.get('bt_mode', 0)}")
    nrs = resp.get("logging_nrs", [])
    if nrs:
        names = ", ".join(f"{get_syscall_name(n)}({n})" for n in nrs[:20])
        print(f"  记录 NR ({len(nrs)}): {names}")
    hooks = resp.get("hooks", [])
    if hooks:
        print(f"  Hook 列表 ({len(hooks)}):")
        for h in hooks[:10]:
            print(f"    {h.get('name')}({h.get('nr')}) [{h.get('method', '?')}]")
    return 0


def cmd_enable(enable: bool):
    """启停监控"""
    cmd = "enable" if enable else "disable"
    ok, resp = kpm_ctl(cmd)
    if ok:
        state = f"{C['G']}已启用{C['W']}" if enable else f"{C['Y']}已停止{C['W']}"
        print(f"✓ 监控 {state}")
        return 0
    print(f"{C['R']}✗ 失败: {resp}{C['W']}")
    return 1


def cmd_set_uid(uid: int):
    ok, resp = kpm_ctl(f"uid {uid}")
    if ok:
        print(f"✓ 目标 UID 设为 {C['B']}{uid}{C['W']}")
        return 0
    print(f"{C['R']}✗ {resp}{C['W']}")
    return 1


def cmd_preset(name: str):
    if name in PRESETS:
        nrs = PRESETS[name]
        ok, resp = kpm_ctl(f"set_nrs {','.join(map(str, nrs))}")
    else:
        ok, resp = kpm_ctl(f"preset {name}")
    if ok:
        print(f"✓ 已应用预设 {C['B']}{name}{C['W']}")
        return 0
    print(f"{C['R']}✗ {resp}{C['W']}")
    return 1


def cmd_set_nrs(nrs_str: str):
    ok, resp = kpm_ctl(f"set_nrs {nrs_str}")
    if ok:
        nrs = [n.strip() for n in nrs_str.split(",")]
        print(f"✓ 已设置 {len(nrs)} 个 NR")
        return 0
    print(f"{C['R']}✗ {resp}{C['W']}")
    return 1


def cmd_drain(args):
    events = kpm_drain(args.max)
    if not events:
        print("没有事件")
        return 0

    # 过滤
    if args.nr:
        nrs = set(args.nr)
        events = [e for e in events if e.get("nr") in nrs]
    if args.tid:
        events = [e for e in events if e.get("pid") == args.tid]
    if args.comm:
        comm_l = args.comm.lower()
        events = [e for e in events if comm_l in (e.get("comm","") or "").lower()]

    # 输出
    limit = min(args.limit or len(events), len(events))
    display = events[-limit:]  # most recent

    print(f"{C['B']}═══ 事件 ({len(display)}/{len(events)}) ═══{C['W']}")
    for e in display:
        print(fmt_event(e, show_bt=args.bt))
    print(f"{C['D']}── 共 {len(display)} 条{C['W']}")

    # 统计
    if args.stat:
        nr_cnt = Counter(e.get("nr") for e in events)
        print(f"\n{C['B']}syscall 分布:{C['W']}")
        for nr, cnt in nr_cnt.most_common(15):
            print(f"  {get_syscall_name(nr)}({nr}): {cnt}")
    return 0


def cmd_watch(args):
    if args.type == "all":
        watch_nrs = set()
        for v in WATCH_TYPES.values():
            watch_nrs.update(v["nrs"])
        config = None
    elif args.type in WATCH_TYPES:
        config = WATCH_TYPES[args.type]
        watch_nrs = config["nrs"]
    else:
        print(f"{C['R']}未知类型: {args.type}。可用: {', '.join(WATCH_TYPES)}{C['W']}")
        return 1

    events = kpm_drain(args.max)
    matched = [e for e in events if e.get("nr") in watch_nrs]
    if args.tid:
        matched = [e for e in matched if e.get("pid") == args.tid]

    print(f"{C['B']}═══ watch:{args.type} — {len(matched)}/{len(events)} 事件 ═══{C['W']}")

    for e in matched[:args.limit or 50]:
        nr = e.get("nr", 0)
        label = (WATCH_TYPES.get(args.type, {})).get("label", "") if config else ""
        if not label:
            for k, v in WATCH_TYPES.items():
                if nr in v["nrs"]:
                    label = f"{k}: {v['label']}"
                    break
        header = label.format(**e) if label else f"{get_syscall_name(nr)}({nr})"
        meta = f"TID={e.get('pid','?')} {e.get('comm','?')}"
        print(f"  {C['B']}{header}{C['W']}  {C['D']}{meta}{C['W']}")
        desc = e.get("desc", "")
        if desc:
            print(f"    {C['G']}{desc[:200]}{C['W']}")
    return 0


def cmd_analyze(args):
    events = kpm_drain(args.max)
    if args.nr:
        events = [e for e in events if e.get("nr") in args.nr]
    if args.tid:
        events = [e for e in events if e.get("pid") == args.tid]
    if args.comm:
        comm_l = args.comm.lower()
        events = [e for e in events if comm_l in (e.get("comm","") or "").lower()]
    if args.search:
        s = args.search.lower()
        events = [e for e in events if s in (e.get("desc","") or "").lower() or s in str(e.get("a0","")).lower() or s in str(e.get("a1","")).lower()]

    if not events:
        print("无匹配事件")
        return 0

    # 统计
    nr_cnt = Counter(e.get("nr") for e in events)
    tid_cnt = Counter(e.get("pid") for e in events)

    print(f"{C['B']}═══ 分析: {len(events)} 事件 ═══{C['W']}")
    print(f"\n{C['B']}syscall 分布 (Top 15):{C['W']}")
    for nr, cnt in nr_cnt.most_common(15):
        bar = "█" * min(40, cnt * 40 // max(1, nr_cnt.most_common(1)[0][1]))
        print(f"  {get_syscall_name(nr)}({nr}): {cnt:4d} {C['D']}{bar}{C['W']}")

    print(f"\n{C['B']}活跃线程 (Top 10):{C['W']}")
    for tid, cnt in tid_cnt.most_common(10):
        comm = next((e.get("comm","?") for e in events if e.get("pid") == tid), "?")
        print(f"  TID={tid:6d} [{comm:16s}]: {cnt} events")

    # 可疑模式检测
    patterns = detect_patterns(events)
    if patterns:
        print(f"\n{C['R']}⚠ 可疑模式:{C['W']}")
        for p in patterns:
            print(f"  {p['sev']} {p['tid']} [{p['comm']}]: {p['pattern']}")

    # 字段详情
    if args.fields:
        fields = [f.strip() for f in args.fields.split(",")]
        print(f"\n{C['B']}字段详情 (Top 30):{C['W']}")
        for e in events[:30]:
            vals = [f"{f}={e.get(f, '?')}" for f in fields]
            print(f"  {get_syscall_name(e.get('nr'))}({e.get('nr')}) | {' | '.join(vals)}")

    return 0


def detect_patterns(events: list) -> list:
    """检测可疑模式"""
    results = []
    tid_nrs = {}
    tid_comm = {}
    for e in events:
        tid = e.get("pid", 0)
        nr = e.get("nr", 0)
        if tid not in tid_nrs:
            tid_nrs[tid] = set()
            tid_comm[tid] = e.get("comm", "?")
        tid_nrs[tid].add(nr)

    for tid, nrs in tid_nrs.items():
        comm = tid_comm.get(tid, "?")
        # 检测线程
        if (56 in nrs or 63 in nrs or 78 in nrs) and (129 in nrs or 131 in nrs or 117 in nrs):
            results.append({"sev": f"{C['R']}🔴", "tid": tid, "comm": comm, "pattern": "检测线程（读进程信息+信号/ptrace）"})
        elif 117 in nrs:
            results.append({"sev": f"{C['R']}🟠", "tid": tid, "comm": comm, "pattern": "ptrace 跟踪/注入"})
        if 222 in nrs and 271 in nrs:
            results.append({"sev": f"{C['R']}🔴", "tid": tid, "comm": comm, "pattern": "内存注入链 (mmap+process_vm_writev)"})
        if 226 in nrs:
            results.append({"sev": f"{C['Y']}🟠", "tid": tid, "comm": comm, "pattern": "mprotect 修改内存权限"})
        if 277 in nrs:
            results.append({"sev": f"{C['Y']}🟠", "tid": tid, "comm": comm, "pattern": "seccomp 安全策略"})
        if 203 in nrs or 206 in nrs:
            results.append({"sev": f"{C['Y']}🟡", "tid": tid, "comm": comm, "pattern": "网络外联"})
    return results


def cmd_threads(args):
    events = kpm_drain(args.max)
    tid_nrs = {}
    tid_comm = {}
    tid_count = Counter()
    for e in events:
        tid = e.get("pid", 0)
        nr = e.get("nr", 0)
        tid_count[tid] += 1
        if tid not in tid_nrs:
            tid_nrs[tid] = set()
            tid_comm[tid] = e.get("comm", "?")
        tid_nrs[tid].add(nr)

    print(f"{C['B']}═══ 线程分析: {len(tid_nrs)} 个线程, {len(events)} 事件 ═══{C['W']}")
    for tid, cnt in tid_count.most_common(20):
        comm = tid_comm.get(tid, "?")
        nrs = tid_nrs.get(tid, set())
        nr_names = ", ".join(f"{get_syscall_name(n)}({n})" for n in sorted(nrs)[:10])
        print(f"  TID={tid:6d} [{comm:16s}] {cnt:4d} events → {nr_names}")
    return 0


def cmd_maps(args):
    ok, out = adb_su(f"cat /proc/{args.pid}/maps")
    if not ok:
        print(f"{C['R']}✗ 无法读取 maps: {out}{C['W']}")
        return 1
    lines = out.split("\n")
    if args.filter:
        lines = [l for l in lines if args.filter.lower() in l.lower()]

    suspicious = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        addr = parts[0]
        perms = parts[1]
        name = parts[5] if len(parts) > 5 else ""
        # 标记可疑
        is_sus = False
        reasons = []
        if "x" in perms:
            if not name or name.startswith("["):
                reasons.append("匿名可执行")
                is_sus = True
            if "memfd" in name:
                reasons.append("memfd")
                is_sus = True
        if is_sus:
            line = f"{C['R']}{line}  ⚠ {', '.join(reasons)}{C['W']}"
            suspicious.append((line, reasons))
        print(line)
    if suspicious:
        print(f"\n{C['R']}⚠ 发现 {len(suspicious)} 个可疑区域{C['W']}")
    return 0


def cmd_resolve(args):
    ok, out = adb_su(f"cat /proc/{args.pid}/maps")
    if not ok:
        print(f"{C['R']}✗ 失败{C['W']}")
        return 1
    # parse maps
    maps = []
    for line in out.split("\n"):
        parts = line.split()
        if len(parts) < 5:
            continue
        rng = parts[0].split("-")
        maps.append({
            "start": int(rng[0], 16), "end": int(rng[1], 16),
            "perms": parts[1], "name": parts[5] if len(parts) > 5 else "[anon]"
        })
    for addr_str in args.addresses:
        addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str, 16) if all(c in "0123456789abcdefABCDEF" for c in addr_str) else int(addr_str)
        for m in maps:
            if m["start"] <= addr < m["end"]:
                off = hex(addr - m["start"])
                print(f"  {addr_str} → {m['name']} + {off} [{m['perms']}]  ({hex(m['start'])}-{hex(m['end'])})")
                break
        else:
            print(f"  {addr_str} → {C['R']}[未映射]{C['W']}")
    return 0


def cmd_get_uid(args):
    ok, out = adb_su(f"pm list packages -U | grep {args.package}")
    if not ok or not out:
        # try dumpsys
        ok, out = adb_su(f"dumpsys package {args.package} | grep userId=")
    if out:
        # extract UID
        m = re.search(r'uid:(\d+)|userId=(\d+)', out)
        if m:
            uid = m.group(1) or m.group(2)
            print(f"  {args.package} → UID={C['B']}{uid}{C['W']}")
        else:
            print(out)
    else:
        print(f"{C['R']}未找到包: {args.package}{C['W']}")
    return 0


def cmd_get_pid(args):
    if args.package:
        ok, out = adb_su(f"pidof {args.package}")
    else:
        ok, out = adb_su(f"ps -A | grep u0_a{args.uid - 10000}")
    if out:
        print(out)
    else:
        print(f"{C['R']}未找到进程{C['W']}")
    return 0


def cmd_session(args):
    """一键监控会话"""
    # 1. resolve UID
    if args.package:
        ok, out = adb_su(f"pm list packages -U | grep {args.package}")
        m = re.search(r'uid:(\d+)', out) if out else None
        uid = int(m.group(1)) if m else None
    else:
        uid = args.uid

    if not uid:
        print(f"{C['R']}无法确定 UID{C['W']}")
        return 1

    print(f"{C['B']}═══ 配置监控会话 ═══{C['W']}")
    print(f"  目标: {args.package or f'UID {uid}'}")

    # 2. set target UID
    ok, _ = kpm_ctl(f"uid {uid}")
    print(f"  {'✓' if ok else '✗'} UID: {uid}")

    # 3. set preset or NRS
    if args.preset:
        if args.preset in PRESETS:
            nrs = PRESETS[args.preset]
            ok, _ = kpm_ctl(f"set_nrs {','.join(map(str, nrs))}")
        else:
            ok, _ = kpm_ctl(f"preset {args.preset}")
    elif args.nrs:
        ok, _ = kpm_ctl(f"set_nrs {args.nrs}")
    else:
        ok, _ = kpm_ctl("preset re_basic")
    preset_name = args.preset or args.nrs or "re_basic"
    print(f"  {'✓' if ok else '✗'} 预设: {preset_name}")

    # 4. configure
    if args.tier2:
        kpm_ctl("tier2 on")
    if args.bt_mode == "length":
        kpm_ctl("bt_mode length")

    # 5. clear old events
    kpm_ctl("clear")

    # 6. enable
    ok, _ = kpm_ctl("enable")
    if ok:
        print(f"\n{C['G']}✓ 监控已启用！{C['W']}")
        print(f"  下一步: 操作目标 App")
        print(f"  拉取事件: {C['B']}python3 svc.py drain --max 500{C['W']}")
    else:
        print(f"\n{C['R']}✗ 启用失败{C['W']}")

    return 0


def cmd_clear():
    ok, _ = kpm_ctl("clear")
    print(f"{'✓ 已清空' if ok else '✗ 失败'}")
    return 0 if ok else 1


def cmd_raw(args):
    ok, resp = kpm_ctl(args.command)
    if ok:
        print(json.dumps(resp, indent=2, ensure_ascii=False) if isinstance(resp, (dict, list)) else resp)
    else:
        print(f"{C['R']}{resp}{C['W']}")
    return 0 if ok else 1


# ═══════════ 主入口 ═══════════

def main():
    parser = argparse.ArgumentParser(
        description="SVCMonitor CLI — Android 内核 SVC 监控工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        示例:
          svc.py status
          svc.py session com.target.app --preset anti_debug
          svc.py watch ptrace --max 300
          svc.py drain --max 200 --nr 56 --stat
          svc.py analyze --nr 222,226 --search "/proc/self/maps"
          svc.py maps 12345 --filter r-xp
          svc.py resolve 12345 0x7a3b4c5000,0x7a3b4c6000
        """))
    sub = parser.add_subparsers(dest="cmd", help="子命令")

    sub.add_parser("status", help="查看模块状态")

    p = sub.add_parser("enable", help="启用监控")
    p = sub.add_parser("disable", help="停止监控")

    p = sub.add_parser("set-uid", help="设置目标 UID")
    p.add_argument("uid", type=int)

    p = sub.add_parser("preset", help="加载预设方案")
    p.add_argument("name", help=f"预设名: {', '.join(PRESETS)}")

    p = sub.add_parser("set-nrs", help="自定义 NR 列表")
    p.add_argument("nrs", help="逗号分隔的 NR，如 56,63,64,129")

    p = sub.add_parser("drain", help="拉取事件")
    p.add_argument("--max", type=int, default=200, help="最多拉取数 (默认200)")
    p.add_argument("--nr", type=int, nargs="+", help="只返回这些 syscall 号")
    p.add_argument("--tid", type=int, help="只返回此 TID")
    p.add_argument("--comm", help="只返回匹配此进程名的事件")
    p.add_argument("--limit", type=int, help="最多显示 N 条 (默认全部)")
    p.add_argument("--bt", action="store_true", help="显示 backtrace")
    p.add_argument("--stat", action="store_true", help="显示统计摘要")

    p = sub.add_parser("watch", help="关注特定 SVC 类型的关键字段")
    p.add_argument("type", choices=list(WATCH_TYPES) + ["all"], help="关注类型")
    p.add_argument("--max", type=int, default=300, help="拉取事件上限")
    p.add_argument("--tid", type=int, help="只关注此 TID")
    p.add_argument("--limit", type=int, default=50, help="最多显示 N 条")

    p = sub.add_parser("analyze", help="字段级深度分析")
    p.add_argument("--max", type=int, default=300, help="分析事件上限")
    p.add_argument("--nr", type=int, nargs="+", help="只分析这些 syscall 号")
    p.add_argument("--tid", type=int, help="只分析此 TID")
    p.add_argument("--comm", help="只分析此进程名")
    p.add_argument("--search", help="在 desc 中搜索关键词")
    p.add_argument("--fields", help="额外显示的字段，逗号分隔 (如 desc,a0,a1,pc)")

    p = sub.add_parser("threads", help="线程行为分析")
    p.add_argument("--max", type=int, default=500, help="分析事件上限")

    p = sub.add_parser("maps", help="获取进程内存映射")
    p.add_argument("pid", type=int)
    p.add_argument("--filter", help="过滤关键词")

    p = sub.add_parser("resolve", help="地址→模块+偏移解析")
    p.add_argument("pid", type=int)
    p.add_argument("addresses", nargs="+", help="十六进制地址列表")

    p = sub.add_parser("get-uid", help="包名→UID")
    p.add_argument("package")

    p = sub.add_parser("get-pid", help="获取进程 PID")
    p.add_argument("--package")
    p.add_argument("--uid", type=int)

    p = sub.add_parser("session", help="一键监控会话")
    p.add_argument("target", nargs="?", help="包名 或 UID(数字)")
    p.add_argument("--preset", default="re_basic", help="预设方案")
    p.add_argument("--nrs", help="自定义 NR 列表")
    p.add_argument("--tier2", action="store_true", help="开启 payload 抓取")
    p.add_argument("--bt-mode", choices=["accurate","length"], default="accurate")

    sub.add_parser("clear", help="清空事件缓冲区")

    p = sub.add_parser("raw", help="执行原始 ctl0 命令")
    p.add_argument("command", help="ctl0 命令")

    args = parser.parse_args()

    dispatch = {
        "status": lambda: cmd_status(),
        "enable": lambda: cmd_enable(True),
        "disable": lambda: cmd_enable(False),
        "set-uid": lambda: cmd_set_uid(args.uid),
        "preset": lambda: cmd_preset(args.name),
        "set-nrs": lambda: cmd_set_nrs(args.nrs),
        "drain": lambda: cmd_drain(args),
        "watch": lambda: cmd_watch(args),
        "analyze": lambda: cmd_analyze(args),
        "threads": lambda: cmd_threads(args),
        "maps": lambda: cmd_maps(args),
        "resolve": lambda: cmd_resolve(args),
        "get-uid": lambda: cmd_get_uid(args),
        "get-pid": lambda: cmd_get_pid(args),
        "session": lambda: cmd_session(args),
        "clear": lambda: cmd_clear(),
        "raw": lambda: cmd_raw(args),
    }

    if args.cmd in dispatch:
        sys.exit(dispatch[args.cmd]())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
