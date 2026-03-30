/**
 * svc_monitor_integration.c — 集成指南
 * 
 * 展示如何将 mem_monitor 嵌入你现有的 svc_monitor.c
 * 
 * 改动量很小, 主要是 4 个接入点:
 * 1. init 中调用 mem_mon_init()
 * 2. exit 中调用 mem_mon_exit()
 * 3. ctl_handler 中转发 mem_mon_ 开头的命令
 * 4. 在现有的 syscall hook 中插入 mem_mon 的回调
 */

/* ═══════════════════════════════════════════════
 * 1. 在 svc_monitor.c 顶部 include
 * ═══════════════════════════════════════════════ */

// #include "mem_monitor.c"   /* 直接 include, 保持单文件风格 */

/* 
 * 或者如果你想保持分文件:
 * 在 Makefile 中: obj-m += svc_monitor.o mem_monitor.o
 * 然后在 svc_monitor.c 中 extern 声明:
 */
// extern int  mem_mon_init(void);
// extern void mem_mon_exit(void);
// extern int  mem_mon_handle_ctl(const char *cmd, char *output, int output_size);
// extern void mem_mon_on_openat(int dfd, const char __user *filename, int flags, unsigned long pc, unsigned long lr);
// extern void mem_mon_on_openat_ret(const char __user *filename, int fd_ret);
// extern void mem_mon_on_read_ret(int fd, char __user *buf, size_t count, ssize_t ret, unsigned long pc, unsigned long lr);
// extern void mem_mon_filter_maps_content(char __user *buf, ssize_t *ret_size);


/* ═══════════════════════════════════════════════
 * 2. 在 kpm_init() 中添加
 * ═══════════════════════════════════════════════ */

/*
 * 找到你的 kpm_init 函数, 在 hook 安装完成后添加:
 */
static long example_kpm_init(const char *args, const char *event, void *__user reserved)
{
    /* ... 你现有的初始化代码 ... */
    
    /* === 新增: 初始化内存监控 === */
    if (mem_mon_init() == 0) {
        printk(KERN_INFO "svc_monitor: mem_monitor extension loaded\n");
    }
    
    return 0;
}


/* ═══════════════════════════════════════════════
 * 3. 在 kpm_exit() 中添加
 * ═══════════════════════════════════════════════ */

static long example_kpm_exit(void *__user reserved)
{
    /* ... 你现有的清理代码 ... */
    
    /* === 新增: 清理内存监控 === */
    mem_mon_exit();
    
    return 0;
}


/* ═══════════════════════════════════════════════
 * 4. 在 ctl_handler 中添加 (最重要)
 * ═══════════════════════════════════════════════ */

/*
 * 找到你的 ctl_handler / handle_ctl0 函数
 * 在命令解析部分添加:
 */
static long example_ctl_handler(const char *args, char *__user out_msg, int outlen)
{
    char output[4096];
    int n = 0;
    
    /* ... 你现有的命令处理 ... */
    
    /* === 新增: 转发 mem_mon_ 命令 === */
    if (strncmp(args, "mem_mon_", 8) == 0) {
        n = mem_mon_handle_ctl(args, output, sizeof(output));
        if (n > 0 && out_msg) {
            copy_to_user(out_msg, output, n);
        }
        return 0;
    }
    
    /* ... 继续你现有的命令处理 ... */
    return 0;
}


/* ═══════════════════════════════════════════════
 * 5. 在 syscall hook 中插入回调 (核心接入)
 * ═══════════════════════════════════════════════ */

/*
 * A) 在你现有的 openat hook 中:
 *    找到 hook_openat / hook_entry_openat 函数
 */
static void example_openat_hook_entry(unsigned long *args, struct pt_regs *regs)
{
    int dfd = (int)args[0];
    const char __user *filename = (const char __user *)args[1];
    int flags = (int)args[2];
    
    /* 你现有的 openat 处理 ... */
    
    /* === 新增 === */
    mem_mon_on_openat(dfd, filename, flags, regs->pc, regs->regs[30]);
}

static void example_openat_hook_exit(unsigned long ret, unsigned long *args)
{
    const char __user *filename = (const char __user *)args[1];
    
    /* === 新增 === */
    mem_mon_on_openat_ret(filename, (int)ret);
}


/*
 * B) 在你现有的 read hook 中 (如果已有) 或新增 read hook:
 *    这是最关键的接入点
 * 
 *    如果你的 svc_monitor 还没有 hook sys_read,
 *    需要添加一个, 或者在 Tier2 中添加
 */

/*
 * 方式一: 如果你已经 hook 了 sys_read (Tier1/Tier2)
 */
static void example_read_hook_exit(
    unsigned long ret,        /* 返回值 = 实际读取字节数 */
    unsigned long *saved_args,
    struct pt_regs *saved_regs)
{
    int fd = (int)saved_args[0];
    char __user *buf = (char __user *)saved_args[1];
    size_t count = (size_t)saved_args[2];
    ssize_t actual_ret = (ssize_t)ret;
    
    /* 你现有的 read 处理 (记录事件等) ... */
    
    /* === 新增: 内存监控扫描 === */
    mem_mon_on_read_ret(fd, buf, count, actual_ret,
                        saved_regs->pc, saved_regs->regs[30]);
    
    /* === 可选: maps 内容过滤 === */
    /* 如果开启了 maps_filter, 在这里修改返回给用户的内容 */
    if (actual_ret > 0) {
        /* 检查是不是 maps fd */
        /* mem_mon_filter_maps_content(buf, &actual_ret); */
        /* 注意: 修改返回值需要特殊处理 */
    }
}

/*
 * 方式二: 如果你还没有 hook sys_read, 需要新增
 *         在你的 tier2_hooks 或 tier1_hooks 中添加:
 */

/*
 * 在你的 install_tier2_hooks() 或类似函数中:
 *
 *   // sys_read = syscall #63
 *   inline_hook_syscalln(63, 3,
 *       hook_entry_read,   // 入口 hook
 *       hook_exit_read);   // 出口 hook (关键! 需要看到返回值和buffer内容)
 *
 * 注意: sys_read 调用极其频繁, 一定要在 hook 里做快速过滤:
 *   - 只处理目标 PID
 *   - 只处理特定 fd (maps 文件) 或小 buffer
 */


/* ═══════════════════════════════════════════════
 * 6. 使用方法 (通过 APP 或 adb)
 * ═══════════════════════════════════════════════ */

/*
 * # 1. 启用内存监控, 指定目标 PID
 * kpmctl mem_mon_enable 12345
 * 
 * # 2. 加载 Frida 检测字符串预设
 * kpmctl mem_mon_preset_frida
 * 
 * # 3. 或者手动添加自定义字符串
 * kpmctl mem_mon_watch "frida"
 * kpmctl mem_mon_watch "LIBFRIDA"
 * kpmctl mem_mon_watch "gum-js"
 * kpmctl mem_mon_watch "xjd-cache"
 * 
 * # 4. 开始运行, 等壳的检测函数跑
 * # ...
 * 
 * # 5. 查看状态 — 看命中了几次
 * kpmctl mem_mon_status
 * 
 * # 输出示例:
 * # === Memory Monitor Status ===
 * # enabled: 1
 * # target_pid: 12345
 * # watch_count: 13
 * # log_entries: 47
 * # --- Stats ---
 * # maps_opens: 8         ← 检测函数打开了8次 maps
 * # maps_reads: 156       ← 读了156次
 * # string_hits: 23       ← 在 buffer 中找到了23次目标字符串
 * # --- Watch Strings ---
 * #   [0] 'frida' (hits: 15)        ← 这个被搜了15次!
 * #   [1] 'LIBFRIDA' (hits: 3)
 * #   [2] 'gum-js-loop' (hits: 5)
 * 
 * # 6. 导出详细日志 — 看每次命中的 PC 和上下文
 * kpmctl mem_mon_dump
 * 
 * # 输出示例:
 * # [1234567] MAPS_READ pid=12345 tid=12350 comm=xjd-thread pc=0x7a1234abcd lr=0x7a1234aa00 nr=63 fd=8 ret=4096 match=0 ctx='7a00000000-7a10000000 r-xp ... /frida-agent-64.so'
 * # [1234570] READ_MATCH pid=12345 tid=12350 comm=xjd-thread pc=0x7a1234abcd lr=0x7a1234aa00 nr=63 fd=3 ret=256 match=0 ctx='frida-agent'
 * 
 * # ↑↑↑ 关键信息:
 * #   pc=0x7a1234abcd  → 这就是检测函数调用 read() 的地址!
 * #   lr=0x7a1234aa00  → 调用者的返回地址
 * #   comm=xjd-thread  → 检测线程名
 * #   tid=12350        → 检测线程 ID
 * #   match=0          → 匹配到 watch_strings[0] 即 "frida"
 * #   ctx=...          → 匹配位置附近的文本
 * 
 * # 7. 用 PC 地址回到 IDA/Frida 分析:
 * #    在 IDA 中: 减去模块基地址得到偏移, 跳转过去
 * #    在 Frida 中: Interceptor.attach(ptr('0x7a1234abcd'), ...)
 * 
 * # 8. 可选: 开启 maps 过滤, 让检测函数看不到 frida
 * kpmctl mem_mon_maps_filter on
 */
