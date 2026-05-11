"""Parse SVC drain formatted output for fingerprint analysis."""
import subprocess, re, sys
from collections import Counter

def drain_batch(max_events=50):
    """Drain a small batch and return parsed events."""
    result = subprocess.run(
        ['python3', 'svc.py', 'drain', '--max', str(max_events)],
        capture_output=True, text=True, timeout=30
    )
    text = result.stdout
    events = []
    for line in text.split('\n'):
        # Format: syscall(NR) | TID=X TGID=Y | comm | pc=0x... | ret=R | desc
        m = re.match(
            r'.*?(\w+)\((-?\d+)\).*?TID=(\d+)\s+TGID=(\d+).*?\|.*?\|.*?ret=(-?\d+).*?\|(.*)',
            line
        )
        if m:
            name, nr, tid, tgid, ret, desc = m.groups()
            events.append({
                'name': name.strip(),
                'nr': int(nr),
                'tid': int(tid),
                'tgid': int(tgid),
                'ret': int(ret),
                'desc': desc.strip(),
            })
    return events

def main():
    all_events = []
    damai_tgids = {28767, 29078}  # cn.damai main + :channel

    print("=== 拉取 SVC 事件 (5批次 x 50) ===\n")
    for i in range(5):
        events = drain_batch(50)
        all_events.extend(events)
        damai_count = sum(1 for e in events if e['tgid'] in damai_tgids)
        print(f"  批次 {i+1}: {len(events)} events, {damai_count} from damai")
        if len(events) < 50:
            break

    # Filter damai events
    damai = [e for e in all_events if e['tgid'] in damai_tgids]
    print(f"\n总事件: {len(all_events)}, 大麦事件: {len(damai)}")

    if not damai:
        print("\n未捕获到大麦事件，可能 App 在后台无活动。")
        print("请操作 App（刷新、点击等）后重试。")
        return

    # NR distribution
    nrs = Counter(e['nr'] for e in damai)
    print(f"\n=== 大麦 Syscall 分布 ===")
    for nr, cnt in nrs.most_common(20):
        names = {e['name'] for e in damai if e['nr'] == nr}
        print(f"  nr={nr} ({','.join(names)}): {cnt}")

    # Categorize by type
    categories = {
        '文件访问 (openat)': lambda e: e['nr'] == 56,
        '文件存在检查 (faccessat)': lambda e: e['nr'] == 48,
        '符号链接读取 (readlinkat)': lambda e: e['nr'] == 78,
        '进程执行 (execve)': lambda e: e['nr'] == 221,
        '内存映射 (mmap)': lambda e: e['nr'] == 222,
        '内存保护 (mprotect)': lambda e: e['nr'] == 226,
        '进程控制 (prctl)': lambda e: e['nr'] == 167,
        '网络连接 (connect)': lambda e: e['nr'] == 203,
        'Socket创建 (socket)': lambda e: e['nr'] == 198,
        'BPF': lambda e: e['nr'] == 280,
        'memfd': lambda e: e['nr'] == 279,
        '信号处理': lambda e: e['nr'] == 134,
    }

    for cat_name, filt in categories.items():
        cat_events = [e for e in damai if filt(e)]
        if cat_events:
            print(f"\n--- {cat_name} ({len(cat_events)}) ---")
            # Deduplicate by desc
            seen = set()
            for e in cat_events:
                desc = e['desc']
                if desc not in seen:
                    seen.add(desc)
                    tgid = e['tgid']
                    label = "主进程" if tgid == 28767 else "channel"
                    print(f"  [{label}] {desc}")

if __name__ == '__main__':
    main()
