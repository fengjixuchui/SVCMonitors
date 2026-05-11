import json, sys
from collections import Counter

with open(sys.argv[1]) as f:
    data = json.load(f)

events = data.get('events', [])
print(f'Events: {len(events)}')

# NR distribution
nrs = Counter(e['nr'] for e in events)
print('\n=== Syscall 分布 ===')
for nr, c in nrs.most_common(20):
    names = {e['name'] for e in events if e['nr'] == nr}
    print(f'  nr={nr} ({",".join(names)}): {c}')

# Process distribution
procs = Counter((e['tgid'], e['comm']) for e in events)
print('\n=== 进程分布 (top 15) ===')
for (tgid, comm), c in procs.most_common(15):
    uids = {e['uid'] for e in events if e['tgid'] == tgid}
    print(f'  TGID={tgid} comm={comm} uid={uids}: {c}')

# openat paths
openat = [e for e in events if e['nr'] == 56]
print(f'\n=== openat 路径 ({len(openat)}) ===')
paths = Counter()
for e in openat:
    d = e.get('desc', '')
    if 'path=' in d:
        p = d.split('path=')[-1].split('   ')[0].strip().strip('"')
        paths[p] += 1
for p, c in paths.most_common(50):
    print(f'  [{c}] {p}')

# ioctl non-binder
ioctls = [e for e in events if e['nr'] == 29 and 'BINDER' not in e.get('desc', '')]
print(f'\n=== ioctl (非Binder, {len(ioctls)}) ===')
for e in ioctls[:15]:
    print(f'  {e["comm"]} tgid={e["tgid"]} {e.get("desc","")}')

# faccessat
faccess = [e for e in events if e['nr'] == 48]
print(f'\n=== faccessat ({len(faccess)}) ===')
for e in faccess[:15]:
    print(f'  {e["comm"]} tgid={e["tgid"]} {e.get("desc","")}')

# readlinkat
rla = [e for e in events if e['nr'] == 78]
print(f'\n=== readlinkat ({len(rla)}) ===')
for e in rla[:15]:
    print(f'  {e["comm"]} tgid={e["tgid"]} {e.get("desc","")}')

# execve
execve = [e for e in events if e['nr'] == 221]
print(f'\n=== execve ({len(execve)}) ===')
for e in execve[:10]:
    print(f'  {e["comm"]} tgid={e["tgid"]} {e.get("desc","")}')

# mmap with prot flags
mmaps = [e for e in events if e['nr'] == 222]
print(f'\n=== mmap ({len(mmaps)}) ===')
for e in mmaps[:15]:
    print(f'  {e["comm"]} tgid={e["tgid"]} {e.get("desc","")}')
