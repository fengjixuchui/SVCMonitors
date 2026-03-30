/**
 * detect_reverser_integration.c — 集成指南
 * 
 * 展示如何将 detect_reverser.c 嵌入你现有的 svc_monitor.c
 * 
 * 改动点 (4步):
 *   1. #include "detect_reverser.c"
 *   2. kpm_init 中调 dr_init()
 *   3. ctl_handler 转发 dr_ 命令
 *   4. syscall hook 出口处调 dr_capture_context()
 * 
 * ⚠️ 关键: detect_reverser 与 mem_monitor 可同时使用,
 *    mem_monitor 看"壳读了什么", detect_reverser 看"壳在找什么"
 * 
 * 目标: Pixel 6 / ARM64 / Android 12 / kernel 5.10.43 / KernelPatch v0.10.7
 */

/* ═══════════════════════════════════════════════
 * 步骤 1: 在 svc_monitor.c 顶部 include
 * ═══════════════════════════════════════════════ */

// 在现有 include 区域添加:
// #include "detect_reverser.c"

// 如果 mem_monitor 也用了, 两个都 include:
// #include "mem_monitor.c"
// #include "detect_reverser.c"


/* ═══════════════════════════════════════════════
 * 步骤 2: 在 kpm_init() 中初始化
 * ═══════════════════════════════════════════════ */

static long example_kpm_init(const char *args, const char *event, void *__user reserved)
{
    /* ... 你现有的初始化 (hook 安装等) ... */
    
    /* === 新增: 初始化 detect_reverser === */
    if (dr_init() == 0) {
        printk(KERN_INFO "svc_monitor: detect_reverser extension loaded\n");
    }
    
    /* 如果同时用 mem_monitor: */
    // if (mem_mon_init() == 0) {
    //     printk(KERN_INFO "svc_monitor: mem_monitor extension loaded\n");
    // }
    
    return 0;
}


/* ═══════════════════════════════════════════════
 * 步骤 3: 在 kpm_exit() 中清理
 * ═══════════════════════════════════════════════ */

static long example_kpm_exit(void *__user reserved)
{
    /* ... 你现有的清理 ... */
    
    /* === 新增 === */
    dr_exit();
    // mem_mon_exit();  /* 如果也用了 mem_monitor */
    
    return 0;
}


/* ═══════════════════════════════════════════════
 * 步骤 4: 在 ctl_handler 中转发命令
 * ═══════════════════════════════════════════════ */

/*
 * 找到你的 ctl_handler / handle_ctl0 函数
 * 在命令解析逻辑中添加 dr_ 前缀的转发:
 */
static long example_ctl_handler(const char *args, char *__user out_msg, int outlen)
{
    char output[4096];
    int n = 0;
    
    /* ... 你现有的命令处理 ... */
    
    /* === 新增: 转发 dr_ 命令到 detect_reverser === */
    if (strncmp(args, "dr_", 3) == 0) {
        n = dr_handle_ctl(args, output, sizeof(output));
        if (n > 0 && out_msg) {
            copy_to_user(out_msg, output, n < outlen ? n : outlen);
        }
        return 0;
    }
    
    /* === 同时保留 mem_mon_ 命令 (如果用了) === */
    if (strncmp(args, "mem_mon_", 8) == 0) {
        n = mem_mon_handle_ctl(args, output, sizeof(output));
        if (n > 0 && out_msg) {
            copy_to_user(out_msg, output, n < outlen ? n : outlen);
        }
        return 0;
    }
    
    /* ... 继续你现有的命令处理 ... */
    return 0;
}


/* ═══════════════════════════════════════════════
 * 步骤 5: 在 syscall hook 出口处插入捕获调用
 *   ★★★ 这是最核心的步骤 ★★★
 * ═══════════════════════════════════════════════ */

/*
 * detect_reverser 需要在 syscall 出口处调用 dr_capture_context()
 * 这个函数会:
 *   - 解引用 x0-x28 寄存器, 提取字符串
 *   - 扫描栈上的字符串指针
 *   - 对 kill/exit_group 做特殊处理 (最有价值)
 * 
 * ⚠️ 重要: 用 hook_exit (出口hook) 而不是 hook_entry (入口hook)
 *    因为出口时寄存器可能还保留着调用者上下文
 *    特别是 read() 返回后, x1(buf) 仍指向 maps 内容
 */

/* === A) sys_read (syscall #63) — 最关键的 hook === */
/*
 * 壳的检测线程在 read() maps 之后,
 * 会拿读到的内容做字符串搜索。
 * 此时寄存器/栈上可能还有 needle 指针。
 * 
 * 但更有价值的是: 在 read() 之前的那一次 syscall (如 nanosleep/futex 等)
 * 或者 read() 之后的下一次 syscall (当它已经在做比较了)
 * 
 * 所以我们不只 hook read, 而是在所有 Tier1/Tier2 hook 出口都插入
 */
static void example_read_hook_exit(
    unsigned long ret,
    unsigned long *saved_args,
    struct pt_regs *saved_regs)
{
    int fd = (int)saved_args[0];
    char __user *buf = (char __user *)saved_args[1];
    size_t count = (size_t)saved_args[2];
    ssize_t actual_ret = (ssize_t)ret;
    
    /* 你现有的 read hook 处理 ... */
    
    /* === 新增: detect_reverser 捕获 === */
    dr_capture_context(saved_regs, 63);  /* 63 = __NR_read */
    
    /* === 新增: mem_monitor 回调 (如果也用了) === */
    // mem_mon_on_read_ret(fd, buf, count, actual_ret,
    //                     saved_regs->pc, saved_regs->regs[30]);
}


/* === B) sys_openat (syscall #56) === */
/*
 * 壳打开 /proc/self/maps 时, 
 * 寄存器里可能有刚解密出来的检测字符串
 */
static void example_openat_hook_exit(
    unsigned long ret,
    unsigned long *saved_args,
    struct pt_regs *saved_regs)
{
    /* 你现有处理 ... */
    
    /* === 新增 === */
    dr_capture_context(saved_regs, 56);  /* 56 = __NR_openat */
}


/* === C) sys_kill (syscall #129) — ★ 最有价值 ★ === */
/*
 * 当壳检测到 Frida 后调用 kill() 自杀,
 * 此时寄存器/栈上几乎一定还有刚才比对过的 needle!
 * 
 * 因为调用链是:
 *   detect_func() {
 *       needle = "frida";          // ← x1 或栈上
 *       while (...) {
 *           if (memmem(buf, needle)) {
 *               kill(getpid(), 9); // ← 这里我们捕获!
 *           }
 *       }
 *   }
 */
static void example_kill_hook_entry(unsigned long *args, struct pt_regs *regs)
{
    /* 你现有处理 ... */
    
    /* === 新增: kill 入口也捕获 (不等出口) === */
    dr_capture_context(regs, 129);  /* 129 = __NR_kill */
}


/* === D) sys_exit_group (syscall #94) — 同样有价值 === */
static void example_exit_group_hook_entry(unsigned long *args, struct pt_regs *regs)
{
    /* === 新增 === */
    dr_capture_context(regs, 94);  /* 94 = __NR_exit_group */
}


/* === E) 通用: 在你的 hook_exit 函数框架中加入 === */
/*
 * 如果你的 svc_monitor.c 有一个统一的 hook 出口处理函数,
 * 可以在那里统一加入, 不用每个 syscall 单独加:
 * 
 * void unified_hook_exit(int syscall_nr, struct pt_regs *regs, ...) {
 *     // 你现有的事件记录逻辑 ...
 *     
 *     // === 新增: 统一捕获 ===
 *     dr_capture_context(regs, syscall_nr);
 * }
 * 
 * 这样所有被 hook 的 syscall 都会触发捕获,
 * detect_reverser 内部会自动判断是否需要处理
 * (检查 PID、TID、syscall_nr 等)
 */


/* ═══════════════════════════════════════════════
 * 步骤 6: 确保 sys_read 已被 hook
 * ═══════════════════════════════════════════════ */

/*
 * 如果你的 svc_monitor.c 还没有 hook sys_read (#63),
 * 必须添加! 它是 mem_monitor 和 detect_reverser 最核心的触发点。
 * 
 * 在你的 tier1_hooks 或 tier2_hooks 数组中添加:
 * 
 * // sys_read: fd, buf, count → 3 个参数
 * inline_hook_syscalln(63, 3,
 *     hook_entry_read,
 *     hook_exit_read);
 * 
 * ⚠️ 性能注意: sys_read 极其频繁!
 * 在 hook 入口做快速过滤:
 * 
 * void hook_entry_read(unsigned long *args, struct pt_regs *regs) {
 *     // 快速过滤: 只处理目标 PID
 *     if (current->tgid != target_pid) return;
 *     // ... 记录参数 ...
 * }
 */


/* ═══════════════════════════════════════════════
 * 完整使用流程 (通过 kpmctl)
 * ═══════════════════════════════════════════════ */

/*
 * ====== 基本使用 ======
 * 
 * # 1. 启用 detect_reverser, 指定目标 APP 的 PID
 * adb shell su -c "kpmctl svc_monitor dr_enable 12345"
 * 
 * # 2. (可选) 添加特定 TID — 只监控壳的检测线程
 * #    通过 ps -T 找到检测线程:
 * adb shell su -c "ps -T -p 12345"
 * #    输出中找到类似 xjd-thread / libmsaoaidsec 的线程
 * adb shell su -c "kpmctl svc_monitor dr_add_tid 12350"
 * adb shell su -c "kpmctl svc_monitor dr_add_tid 12351"
 * 
 * # 3. 让 APP 正常运行, 等壳执行检测
 * #    壳会读 maps → 搜索字符串 → (如果找到就 kill)
 * #    detect_reverser 会在每个 syscall 出口捕获寄存器中的字符串
 * 
 * # 4. ★ 查看捕获到的"针" — 这就是壳在找什么! ★
 * adb shell su -c "kpmctl svc_monitor dr_needles"
 * 
 * # 输出示例:
 * # === Captured Detection Strings (7 unique) ===
 * # [0] "frida"
 * #     hits=23  via=register(x1)  addr=0x7a1234abcd
 * #     pc=0x7a00005678  lr=0x7a00005600  tid=12350  comm=xjd-thread  nr=63
 * # [1] "gum-js-loop"
 * #     hits=5   via=ptr_array(x2)  addr=0x7a12350000
 * #     pc=0x7a00005678  lr=0x7a00005600  tid=12350  comm=xjd-thread  nr=129
 * # [2] "gmain"
 * #     hits=8   via=register(x3)  addr=0x7a00abcdef
 * # [3] "linjector"
 * #     hits=2   via=stack(sp+0x48) addr=0x7b00001234
 * # [4] "/data/local/tmp"
 * #     hits=12  via=register(x0)  addr=0x7b88880000
 * # [5] "re.frida.server"
 * #     hits=3   via=ptr_array(x4) addr=0x7a99990000
 * # [6] "libfrida"
 * #     hits=1   via=register(x1)  addr=0x7a1234ff00
 * #     pc=0x7a00005678  tid=12350  nr=129    ← 在 kill() 时捕获!
 * 
 * # ★ 解读:
 * #   - 壳在检测 7 种字符串!
 * #   - "frida" 被搜索了 23 次 (最频繁)
 * #   - nr=129 表示在 kill() 时捕获, 说明壳检测到后正在自杀
 * #   - pc=0x7a00005678 是检测函数的地址
 * #   - 用这个 PC 去 IDA 里看, 就能找到完整的检测逻辑
 * 
 * 
 * ====== 高级用法 ======
 * 
 * # 查看详细的上下文 dump (包含所有寄存器和栈)
 * adb shell su -c "kpmctl svc_monitor dr_dump 0"
 * 
 * # 输出:
 * # === Context Dump #0 ===
 * # time=12345678 pid=12345 tid=12350 comm=xjd-thread nr=63
 * # pc=0x7a00005678 sp=0x7fc1234500 lr=0x7a00005600
 * # --- Registers with strings ---
 * #   x0 = 0x7fc1234800 → "/proc/self/maps"
 * #   x1 = 0x7a1234abcd → "frida"
 * #   x3 = 0x7a00abcdef → "gmain"
 * # --- Stack strings ---
 * #   [sp+0x48] → 0x7b00001234 → "linjector"
 * #   [sp+0x90] → 0x7b00005678 → "/data/local/tmp"
 * 
 * # 配置选项
 * adb shell su -c "kpmctl svc_monitor dr_config stack_scan on"   # 开启栈扫描
 * adb shell su -c "kpmctl svc_monitor dr_config full_dump on"    # 保存完整上下文
 * adb shell su -c "kpmctl svc_monitor dr_config all_threads on"  # 监控所有线程
 * 
 * # 查看统计
 * adb shell su -c "kpmctl svc_monitor dr_status"
 * 
 * # 清除数据 (开始新的捕获)
 * adb shell su -c "kpmctl svc_monitor dr_clear"
 * 
 * 
 * ====== 配合 mem_monitor 使用 ======
 * 
 * # detect_reverser 告诉你壳在找什么 (needle)
 * # mem_monitor 告诉你壳读了什么 (haystack)
 * # 两个一起用可以完整还原检测逻辑:
 * 
 * # 1. 同时启用两个模块
 * kpmctl svc_monitor dr_enable 12345
 * kpmctl svc_monitor mem_mon_enable 12345
 * kpmctl svc_monitor mem_mon_preset_frida
 * 
 * # 2. 运行后查看
 * kpmctl svc_monitor dr_needles        # 壳找什么
 * kpmctl svc_monitor mem_mon_status     # 壳读什么
 * kpmctl svc_monitor mem_mon_dump       # 详细的读取日志
 * 
 * # 3. 完整的逆向图:
 * #    mem_monitor: 壳打开 /proc/self/maps → 读取内容 → 匹配到 "frida"
 * #    detect_reverser: 壳用 x1="frida" x3="gmain" 做比对, PC=0x7a00005678
 * #    → 在 IDA 中跳转到 0x7a00005678, 就能看到完整的检测函数!
 * 
 * 
 * ====== 配合 Web 前端使用 ======
 * 
 * # Web 前端新增了 "Detection Reverser" tab,
 * # 通过 API 获取 kpmctl 输出并可视化展示。
 * # 
 * # 启动 Web 服务后访问 mem_analyzer 页面,
 * # 点击 "Detection Reverser" tab 即可:
 * # - 一键启用/配置 detect_reverser
 * # - 实时查看捕获到的 needle 列表
 * # - 查看上下文 dump 详情
 * # - 直接跳转到 Disassembler 分析检测函数 PC
 * # - 生成 Frida hook 脚本 patch 掉检测
 */
