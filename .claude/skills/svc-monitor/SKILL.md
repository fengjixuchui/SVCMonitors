---
name: svc-monitor
description: Android 内核级 SVC 系统调用监控与分析。通过 adb CLI 控制 KernelPatch KPM，在 ARM64 内核层 hook syscall，捕获目标进程所有系统调用事件。适用：反调试对抗、风控指纹采集、加壳检测、算法还原、Frida/IDA 联动。
version: 1.1.0
---

# SVC Monitor — 内核 Syscall 监控

## 前置要求

- **已 root 的 Android 设备**，安装 KernelPatch（APatch 亦可）
- **KPM 模块已加载**：`svc_monitor.kpm` 编译自 `kpm/src/svc_monitor.c`
- **adb 可用**：`adb devices` 能看到设备
- **Python 3.8+**：运行 `svc.py` 和 MCP server

验证 KPM 是否正常：
```bash
python3 svc.py status          # 应返回 JSON：enabled 状态、target_uid、events_buffered 等
```

## 工具

CLI 位于项目根目录：`python3 svc.py <命令>`

所有捕获的事件建议保存到 `analysis/` 目录下：
```bash
mkdir -p analysis
python3 svc.py drain --max 500 --output analysis/events.json
```

---

## 完整 CLI 命令参考

### 状态与生命周期
```bash
python3 svc.py status                      # 查询模块状态 JSON（enabled/uid/nrs/buffered/dropped）
python3 svc.py enable                      # 启动 syscall 记录
python3 svc.py disable                     # 停止 syscall 记录
python3 svc.py clear                       # 清空事件缓冲区
```

### 目标与配置
```bash
python3 svc.py get-uid <包名>               # 包名 → UID
python3 svc.py get-pid --package <包名>     # 确认进程 PID
python3 svc.py get-pid --uid <UID>          # 通过 UID 查 PID
python3 svc.py set-uid <UID>                # 设置目标 UID 过滤（只记录该 UID 的 syscall）
python3 svc.py preset <方案名>               # 加载预设 NR 列表
python3 svc.py set-nrs <NR,NR,...>          # 自定义 syscall 号列表（逗号分隔）
```

### 数据采集
```bash
python3 svc.py drain [--max N] [--nr N,N] [--tid TID] [--comm NAME] [--bt] [--stat] [--output FILE]
python3 svc.py watch <类型> [--limit N] [--output FILE]
# watch 支持的类型: ptrace, kill, mmap, mprotect, openat, read, write,
#                   clone, execve, connect, process_vm, prctl, seccomp, bpf,
#                   faccessat, all
python3 svc.py analyze [--nr N,N] [--search STR] [--fields F1,F2] [--output FILE]
# analyze 输出: syscall 分布柱状图、线程活跃度排行、异常模式检测
python3 svc.py threads [--max N]            # 按 TID 分组，展示每线程 syscall 使用模式
```

### 地址解析
```bash
python3 svc.py maps <PID> [--filter r-xp]    # 读取 /proc/PID/maps，高亮可疑段
python3 svc.py resolve <PID> <地址1> <地址2>  # 地址 → libXXX.so+0xOFFSET
```

### 快捷会话
```bash
python3 svc.py session <包名> --preset <方案> [--tier2]   # 一键配置+启用
python3 svc.py raw "<ctl0 命令>"                           # 直接发 ctl0 命令到 KPM
```

---

## 预设方案完整 NR 清单

| 方案名 | 数量 | 包含的 syscall |
|--------|------|---------------|
| **re_basic** | 14 | 56(openat), 48(faccessat), 78(readlinkat), 221(execve), 222(mmap), 226(mprotect), 198(socket), 203(connect), 117(ptrace), 167(prctl), 29(ioctl), 134(sigaction), 279(eventfd2), 280(epoll_create1) |
| **re_full** | 42 | re_basic + 63(read), 64(write), 79(getcwd), 80(chdir), 200(bind), 202(listen), 206(sendto), 207(recvfrom), 129(kill), 130(tkill), 131(tgkill), 215(munmap), 220(clone), 227(msync), 277(seccomp), 278(getrandom), 291(epoll_pwait), 等 |
| **file** | 21 | 56(openat), 34(mkdirat), 35(unlinkat), 38(renameat), 48(faccessat), 57(open), 59(readlink), 63(read), 64(write), 78(readlinkat), 79(getcwd), 80(chdir), 94(fchmodat), 等 |
| **net** | 13 | 198(socket), 200(bind), 201(listen), 202(listen), 203(connect), 206(sendto), 207(recvfrom), 208(getpeername), 209(getsockname), 等 |
| **proc** | 14 | 220(clone), 435(clone3), 221(execve), 93(exit), 94(exit_group), 109(setpgid), 等 |
| **mem** | 9 | 215(munmap), 216(mremap), 219(madvise), 222(mmap), 226(mprotect), 270(process_vm_readv), 271(process_vm_writev), 等 |
| **security** | 15 | 117(ptrace), 129(kill), 130(tkill), 131(tgkill), 134(sigaction), 167(prctl), 277(seccomp), 等 |
| **anti_debug** | 7 | 117(ptrace), 129(kill), 131(tgkill), 134(sigaction), 167(prctl), 220(clone), 435(clone3) |
| **fingerprint** | 6 | 29(ioctl), 56(openat), 63(read), 160(uname), 167(prctl), 278(getrandom) |
| **proc_scan** | 10 | 56, 63, 78, 79, 80, 222, 226, 117, 270, 271 |
| **crypto** | 8 | 56, 29, 25(mount), 63, 64, 215, 222, 226 |
| **binder** | 8 | 29, 291(epoll_pwait), 198, 200, 202, 203, 206, 207 |

使用建议：先用 `re_basic`（14 个 NR，缓冲区压力小）快速摸底，发现疑点后再切 `re_full` 或自定义 NR。

---

## 分析决策树

### 第 1 步：确认目标
```bash
python3 svc.py get-uid <包名>                    # 获取 UID
python3 svc.py get-pid --package <包名>          # 确认进程在运行
```

### 第 2 步：根据分析目的选择监控方案

| 分析目的 | 推荐 preset | 关注 SVC | 关键字段 |
|---------|------------|---------|---------|
| **反调试/Frida检测** | `re_full` | ptrace(117), kill(129), tgkill(131), prctl(167), clone(220) | a0-a2, desc, clone_fn, bt |
| **风控指纹** | `fingerprint` | openat(56), ioctl(29), getrandom(278), faccessat(48) | desc(路径), a1, a2 |
| **加壳/自修改** | `mem` + `file` | mmap(222), mprotect(226), munmap(215), openat(56), read(63) | a1(len), a2(prot/flags), desc |
| **内存注入** | `proc_scan` | process_vm_writev(271), mmap(222), ptrace(117) | a0(pid), a1(addr), desc |
| **网络行为** | `net` | connect(203), sendto(206), socket(198), bind(200) | a1(sockaddr), desc |
| **进程管理** | `proc` | clone(220), clone3(435), execve(221), exit(93) | clone_fn, a0(flags), desc |
| **加密算法** | `crypto` | mmap(222), mprotect(226), read(63), write(64) | desc, a1(len), a2(prot), ret |

### 第 3 步：启动监控
```bash
python3 svc.py session <包名> --preset <方案> --tier2   # 如需 payload 抓取
# 或分步手动控制
python3 svc.py set-uid <UID>
python3 svc.py preset re_full
python3 svc.py enable
```

### 第 4 步：触发行为 + 采集
```bash
# 操作目标 App 后立即拉取
python3 svc.py drain --max 500 --stat --output analysis/round1.json
python3 svc.py watch ptrace --limit 30 --output analysis/ptrace.json
```

### 第 5 步：分析日志

**5a. 找检测线程**
```
python3 svc.py threads --max 500
```
观察：某个 TID 如果同时出现 openat(/proc/self/maps) + read + kill/tgkill → 高度疑似检测线程。
找到可疑 TID 后，用 `--tid` 过滤该线程的所有事件。

**5b. 找 inline SVC（壳的痕迹）**
```
python3 svc.py drain --max 200 --bt --output analysis/bt.json
```
观察 pc 字段：
- pc 在 libc.so / linker64 范围 → 正常 libc 调用
- pc 在匿名段或壳的 SO 内 → **inline SVC**，说明代码绕过了 libc

**5c. 找指纹采集**
```
python3 svc.py analyze --nr 56 --search "/proc/" --output analysis/proc.json
python3 svc.py analyze --nr 56 --search "/sys/" --output analysis/sys.json
```
观察 desc 中的路径：/proc/self/status（进程信息）、build.prop（设备型号）、/sys/devices（硬件信息）

**5d. 找内存注入**
```
python3 svc.py analyze --nr 222,226,271 --fields desc,a0,a1,a2 --output analysis/mem.json
```
观察 mmap 的 prot + MAP_ANONYMOUS + RWX → 注入代码
process_vm_writev（pid=其他进程） → 跨进程注入

**5e. 解析 backtrace 定位代码**
```
python3 svc.py maps <TGID> --filter r-xp
python3 svc.py resolve <TGID> <address1> <address2>
```
将可疑地址解析为 libXXX.so + 0xOFFSET，然后交给 IDA 反汇编。

### 第 6 步：决策是否需要调整

- **过多**（>1000）：增加过滤 `--nr 56,117,129` 缩小范围
- **过少**（<10）：检查 preset 是否正确，或直接用 `set-nrs` 自定义列表
- **无关事件多**：用 `--comm` 过滤目标进程名

---

## 实战工作流示例

### 示例 A：反调试检测分析

```bash
# 1. 确认目标
python3 svc.py get-uid com.example.app              # → UID 10123
python3 svc.py get-pid --package com.example.app    # → PID 12345

# 2. 配置并启动
python3 svc.py set-uid 10123
python3 svc.py preset anti_debug
python3 svc.py enable

# 3. 操作 App（触发检测逻辑），然后立刻拉取
python3 svc.py drain --max 500 --bt --stat --output analysis/anti_debug_1.json

# 4. 分析：找检测线程、看 ptrace 事件
python3 svc.py threads --max 500
python3 svc.py watch ptrace --limit 50

# 5. 定位检测代码
python3 svc.py maps 12345 --filter r-xp              # 查看 SO 布局
python3 svc.py resolve 12345 0x7a1b2c3000 0x7a1b2c4567
# → libnative.so+0x124567 → IDA 跳转反汇编
```

### 示例 B：风控指纹采集

```bash
python3 svc.py session com.example.app --preset fingerprint
python3 svc.py drain --max 200 --output analysis/fp_launch.json
# ...操作 App（登录、支付）...
python3 svc.py drain --max 200 --output analysis/fp_login.json

# 提取文件访问指纹
python3 svc.py analyze --nr 56 --search "/proc/" --output analysis/fp_proc.json
python3 svc.py analyze --nr 56 --search "/sys/" --output analysis/fp_sys.json
python3 svc.py analyze --nr 56 --search "build.prop" --output analysis/fp_build.json

# 汇总：App 读取了哪些 /proc/self/*、/sys/devices/*、build.prop → 风控因子
```

### 示例 C：加壳检测与脱壳辅助

```bash
python3 svc.py session com.example.app --preset mem
python3 svc.py drain --max 1000 --bt --output analysis/packer.json

# 找壳入口：pc 不在 libc.so 的 mmap → 壳的 inline SVC
python3 svc.py analyze --nr 222 --fields desc,pc,bt --output analysis/mmap.json

# 找 DEX 解密时机：openat .dex + 大量 read
python3 svc.py analyze --nr 56 --search ".dex" --output analysis/dex_open.json
python3 svc.py analyze --nr 63 --fields desc,a0,a1,a2 --output analysis/read.json
```

---

## 敏感行为速查

| 模式 | NR 组合 | 含义 |
|------|---------|------|
| 打开 proc/self/maps | 56 + desc 含 "/proc/self/maps" | 扫描自身内存布局 |
| ptrace PTRACE_ATTACH | 117 + a0=16 | Frida 注入检测 |
| kill SIGKILL | 129 + a1=9 | 强制杀进程/线程 |
| mprotect +X | 226 + a2 含 PROT_EXEC | 修改内存为可执行 |
| mmap RWX | 222 + a2=7 | 映射可读可写可执行内存 |
| process_vm_writev 跨进程 | 271 + a0≠自身 | 跨进程内存写入 |
| prctl PR_SET_DUMPABLE | 167 + a0=4 | 设置不可 dump（防 gdb） |
| seccomp | 277 + 任意 | 限制 syscall 白名单 |
| clone + 匿名入口 | 220/435 + clone_fn 指向匿名段 | 动态生成检测代码 |
| connect 非 localhost | 203 + sockaddr 非 127.x | 网络上报 |

## 事件字段解读

| 字段 | 来源 | 分析意义 |
|------|------|---------|
| `nr` | ARM64 syscall 号 | 操作类型（对照 svc调用号.md） |
| `tgid` | 进程 PID | 目标进程 |
| `pid` | 内核 TID（用户态 tid） | 区分线程 |
| `pc` | 调用指令地址 | 是否 inline SVC（不在 libc 范围内说明绕过 libc） |
| `caller` | LR 返回地址 | 上层调用者 |
| `bt` | 栈回溯地址列表 | 完整调用链（注意：内核虚拟地址 0xffffff...） |
| `desc` | 内核态参数解析 | 可读的操作描述（路径、标志位等） |
| `a0-a5` | syscall 6 个参数 | 操作对象（PID、地址、长度、权限等） |

---

## Frida / IDA 联动

### 地址对齐管线
```bash
# 1. 从事件提取可疑 pc 地址
python3 svc.py drain --max 200 --bt --output analysis/bt.json

# 2. 用 maps 找到对应 SO 和基址
python3 svc.py maps <PID> --filter r-xp

# 3. 地址解析为 SO + 偏移
python3 svc.py resolve <PID> 0x7a1b2c3000 0x7a1b2c4567
# → 0x7a1b2c3000 → libnative.so+0x123000
# → 0x7a1b2c4567 → libnative.so+0x124567

# 4. IDA 中打开 libnative.so，跳转到 0x124567 反汇编
```

### Frida hook 辅助
```bash
# 发现某 SO 中大量 inline SVC → 该 SO 绕过 libc
# 用 resolve 定位函数后，Frida Interceptor 替换：
# Interceptor.attach(Module.findExportByName("libnative.so", "detect"), { ... })

# 发现 mmap RWX → 壳在解密代码，Frida 在 mmap 返回后 dump 内存：
# Interceptor.attach(Module.findExportByName(null, "mmap"), {
#   onLeave(retval) { if (this.prot == 7) dump(retval, this.size); }
# })
```

### PC Viewer 实时监控
```bash
cd SVC_PC_View && bash run_app_socket.sh
# 浏览器打开 http://localhost:5000
# 实时查看：syscall 热力图、TID 对话追踪、Maps 视图（高亮可疑段）、Strings 聚合面板
```

---

## MCP Server 使用

让 Claude、Cursor 等 AI 助手通过 MCP 协议直接控制监控。

### 安装
```bash
cd SVCMonitor-MCP-Skill
pip install -r requirements.txt
bash start.sh check           # 检查设备连接和 KPM 状态
```

### 配置到 AI 助手
在项目 `.claude/settings.local.json` 中添加：
```json
{
  "mcpServers": {
    "svc-monitor": {
      "command": "python3",
      "args": ["svc_monitor_mcp.py"],
      "cwd": "/path/to/SVCMonitor-MCP-Skill",
      "env": { "KPATCH_KEY": "your-superkey" }
    }
  }
}
```

### MCP 提供的 13 个工具
`status`, `get_uid`, `get_pid`, `set_target`, `apply_preset`, `set_custom_nrs`, `enable`, `disable`, `drain_events`, `clear_buffer`, `analyze_events`, `get_maps`, `resolve_address`

### 远程设备 SSE 模式
```bash
bash start.sh sse             # 启动 SSE server，通过 HTTP 供远程 AI 助手访问
```

---

## 常见问题排查

### Q: `status` 返回空或报错
KPM 模块未加载，或 ctl0 路径不对。
```bash
adb shell "su -c 'cat /proc/kallsyms | grep ctl0'"
python3 svc.py raw "status"     # 直接用 ctl0 试探
```

### Q: `drain` 返回空数组
1. `enable` 是否已执行？`python3 svc.py status` 检查 `enabled` 字段
2. 目标 App 是否在运行？`python3 svc.py get-pid --package <包名>` 确认
3. UID 是否设对？`python3 svc.py get-uid <包名>` 重新确认
4. NR 列表是否被清空？`status` 检查 `nrs` 字段

### Q: 事件丢失（drain 数量明显少于预期）
内核缓冲区只有 8192 槽位，全量监控几秒就满。
- 先用小 preset（如 `anti_debug`），不要一上来用 `re_full`
- 触发行为后立即 drain（越快越好）
- 用 `--stat` 查看 dropped 数量：dropped > 0 说明溢出

### Q: 事件 desc 乱码
某些 syscall 参数是二进制数据（ioctl 的 struct、connect 的 sockaddr）：
```bash
python3 svc.py drain --max 100 --fields nr,tgid,pid,a0,a1,a2   # 看 raw hex
```

### Q: backtrace 地址无法解析
bt 中的地址是内核虚拟地址（0xffffff...），maps 里的是用户态地址（0x7...）。用 `resolve` 时使用 pc/caller 字段的地址，而非 bt 字段。

### Q: adb 设备断连
```bash
adb kill-server && adb start-server && adb devices
```

---

## 注意事项

- 内核缓冲区 8192 事件，全量监控几秒就满，务必及时 drain
- `svc.py watch` 和 `svc.py analyze` 内部也会 drain，消耗缓冲区
- 先设 preset 再 enable，顺序不能反
- backtrace 地址是内核虚拟地址（0xffffff...），maps 里的是用户态地址（0x7...），不要混淆
- desc 乱码说明是二进制数据，用 `--fields` 查看 hex
- **path_keywords 不要放 App 完整包名**：KPM 的 path_keywords 用 strstr 匹配，放了完整包名会导致 App 自己打不开自身 APK（路径中包含包名被误拦截）
