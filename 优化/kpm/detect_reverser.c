/**
 * detect_reverser.c — 逆向壳的检测行为
 * 
 * 核心目标: 搞清楚壳在检测什么，而不是内存里有什么
 * 
 * 设计思路:
 * ═════════
 * 壳的检测函数自己实现 memmem/strstr，不走 libc。
 * 但它做逐字节比对时，needle 一定在内存里。
 * 
 * 我们用两种策略来抓 needle:
 * 
 * 策略1: 【比对陷阱】
 *   在内存中布置一块"蜜罐区域"，里面放已知内容。
 *   当壳扫描到这个区域并试图逐字节比对时，
 *   我们通过内核 fault handler 看它在比对什么。
 *   
 *   实现方式:
 *   - mmap 一块内存，写入特殊标记
 *   - 通过内核把这块内存的 PTE 标记为特殊状态
 *   - 壳扫描到这块内存时触发 fault
 *   - fault handler 中 dump 此刻寄存器 → 寄存器里有 needle 指针
 * 
 * 策略2: 【Syscall 上下文 dump】(更实用, 不需要改页表)
 *   壳的检测线程在做内存扫描时, 一定会周期性地:
 *   - 调 read() 读 /proc/self/maps
 *   - 调 read() 或 process_vm_readv 读内存区域  
 *   - 最终调 kill/exit 触发结果
 *   
 *   在这些 syscall 的 hook 里:
 *   - 保存完整的 pt_regs (x0-x30, sp, pc, lr)
 *   - 扫描所有寄存器指向的用户态内存, 提取其中的字符串
 *   - 扫描用户态栈帧, 提取栈上的字符串指针
 *   
 *   这样就能看到: 检测函数在调 syscall 的那一刻, 手里拿着什么字符串
 * 
 * 策略3: 【数据段 diff】(最简单)
 *   壳的检测字符串如果是从加密存储解密出来的,
 *   那解密后一定写到某个内存位置。
 *   - 在壳启动前 dump 一次目标区域
 *   - 壳启动后 dump 一次
 *   - diff 两次的差异 → 新出现的字符串就是检测目标
 *   
 *   这个不需要内核, Frida 就能做。但内核做更隐蔽。
 * 
 * 目标: Pixel 6 / ARM64 / Android 12 / kernel 5.10.43
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/ptrace.h>

/* ═══════════════════════════════════════════════
 * 配置
 * ═══════════════════════════════════════════════ */

#define DR_MAX_CAPTURED_STRINGS  256   /* 最多捕获256个不同的字符串 */
#define DR_MAX_STR_LEN           256   /* 单个字符串最大长度 */
#define DR_MAX_DUMP_ENTRIES      1024  /* 上下文 dump 最大条目 */
#define DR_STACK_SCAN_DEPTH      512   /* 栈扫描深度 (字节) */
#define DR_REG_DEREF_MAX         256   /* 解引用寄存器指向的内存最大字节 */

/* ═══════════════════════════════════════════════
 * 数据结构
 * ═══════════════════════════════════════════════ */

/* 捕获到的"壳在找的字符串" */
struct captured_needle {
    char value[DR_MAX_STR_LEN];
    int  len;
    unsigned long found_at;         /* 在哪个内存地址找到的 */
    unsigned long found_via_reg;    /* 通过哪个寄存器找到的 (0=x0, 30=lr, 99=stack) */
    unsigned long pc_when_found;    /* 发现时的 PC */
    unsigned long lr_when_found;    /* 发现时的 LR */
    pid_t tid_when_found;           /* 发现时的 TID */
    char comm[16];                  /* 线程名 */
    int  syscall_nr;                /* 发现时正在执行的 syscall */
    int  hit_count;                 /* 这个字符串被看到几次 */
    unsigned long first_seen_ns;
    unsigned long last_seen_ns;
};

/* 完整的寄存器+内存快照 */
struct context_dump {
    unsigned long timestamp_ns;
    pid_t pid;
    pid_t tid;
    char comm[16];
    int syscall_nr;
    unsigned long pc;
    unsigned long sp;
    unsigned long lr;
    unsigned long regs[31];         /* x0-x30 */
    
    /* 每个寄存器解引用后的内容 */
    struct {
        unsigned long addr;          /* 寄存器的值 (作为地址) */
        int  valid;                  /* 是否是合法用户态地址 */
        char content[64];            /* 解引用后的内容 (前64字节) */
        int  is_string;              /* 看起来像字符串? */
        char string_val[128];        /* 如果是字符串, 值 */
    } reg_deref[31];
    
    /* 栈上的字符串 */
    int stack_string_count;
    struct {
        unsigned long stack_offset;  /* 相对 SP 的偏移 */
        unsigned long ptr_value;     /* 栈上存的指针值 */
        char string_val[128];        /* 指针指向的字符串 */
    } stack_strings[32];
};

/* ═══════════════════════════════════════════════
 * 全局状态
 * ═══════════════════════════════════════════════ */

static struct {
    int enabled;
    pid_t target_pid;
    
    /* 目标线程 (检测线程) 的 TID 列表 */
    pid_t target_tids[16];
    int target_tid_count;
    int capture_all_threads;        /* 1=不限线程, 捕获所有 */
    
    /* 捕获到的 needles */
    struct captured_needle needles[DR_MAX_CAPTURED_STRINGS];
    int needle_count;
    
    /* 上下文 dumps */
    struct context_dump *dumps;
    int dump_count;
    int dump_max;
    
    /* 统计 */
    unsigned long stat_syscalls_scanned;
    unsigned long stat_regs_derefed;
    unsigned long stat_strings_found;
    unsigned long stat_new_needles;
    
    /* 配置 */
    int capture_on_read;            /* 在 read() 时捕获 */
    int capture_on_kill;            /* 在 kill/exit 时捕获 */
    int capture_on_openat;          /* 在 openat 时捕获 */
    int dump_full_context;          /* 是否保存完整上下文 */
    int scan_stack;                 /* 是否扫描栈 */
    
    volatile int lock;
} g_dr;

/* ═══════════════════════════════════════════════
 * Spinlock
 * ═══════════════════════════════════════════════ */
static inline void dr_lock(void) {
    int tmp;
    asm volatile(
        "1: ldaxr %w0, [%1]\n"
        "   cbnz  %w0, 1b\n"
        "   mov   %w0, #1\n"
        "   stxr  %w0, %w0, [%1]\n"
        "   cbnz  %w0, 1b\n"
        : "=&r"(tmp) : "r"(&g_dr.lock) : "memory"
    );
}
static inline void dr_unlock(void) {
    asm volatile("stlr wzr, [%0]\n" : : "r"(&g_dr.lock) : "memory");
}

/* ═══════════════════════════════════════════════
 * 工具函数
 * ═══════════════════════════════════════════════ */

/* 检查一个地址是否是合法的用户态地址 */
static inline int is_user_addr(unsigned long addr)
{
    /* ARM64 用户态地址空间: 0 ~ 0x0000FFFFFFFFFFFF (48-bit) */
    return addr > 0x1000 && addr < 0x0001000000000000UL;
}

/* 安全地从用户态地址读取内容 */
static int safe_read_user(unsigned long addr, char *buf, int size)
{
    if (!is_user_addr(addr))
        return -1;
    if (!access_ok((void __user *)addr, size))
        return -1;
    if (__copy_from_user(buf, (void __user *)addr, size))
        return -1;
    return 0;
}

/* 检查一块内存是否看起来像可打印字符串 */
static int extract_string(unsigned long addr, char *out, int max_len)
{
    char buf[DR_REG_DEREF_MAX];
    int i, len = 0;
    
    if (safe_read_user(addr, buf, sizeof(buf)) != 0)
        return 0;
    
    /* 找可打印字符串 */
    for (i = 0; i < sizeof(buf) && i < max_len - 1; i++) {
        if (buf[i] >= 32 && buf[i] < 127) {
            out[len++] = buf[i];
        } else if (buf[i] == 0 && len >= 3) {
            /* null terminator, 且至少3个字符 */
            break;
        } else if (len >= 3) {
            break;
        } else {
            return 0;  /* 太短, 不是字符串 */
        }
    }
    
    if (len < 3)
        return 0;
    
    out[len] = '\0';
    return len;
}

/* 判断是否是目标线程 */
static int is_target_thread(void)
{
    int i;
    if (!g_dr.enabled)
        return 0;
    if (g_dr.target_pid && current->tgid != g_dr.target_pid)
        return 0;
    if (g_dr.capture_all_threads)
        return 1;
    for (i = 0; i < g_dr.target_tid_count; i++) {
        if (current->pid == g_dr.target_tids[i])
            return 1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════
 * 核心: 捕获检测线程的 "needle"
 * 
 * 在 syscall hook 中调用, 扫描当前寄存器和栈,
 * 提取所有看起来像字符串的值
 * ═══════════════════════════════════════════════ */

/* 添加一个新发现的 needle (去重) */
static void add_needle(const char *str, int len, unsigned long found_at,
                       int found_via_reg, unsigned long pc, unsigned long lr,
                       int syscall_nr)
{
    int i;
    
    /* 去重: 检查是否已经捕获过 */
    dr_lock();
    for (i = 0; i < g_dr.needle_count; i++) {
        if (g_dr.needles[i].len == len &&
            memcmp(g_dr.needles[i].value, str, len) == 0) {
            /* 已存在, 更新计数 */
            g_dr.needles[i].hit_count++;
            g_dr.needles[i].last_seen_ns = ktime_get_ns();
            dr_unlock();
            return;
        }
    }
    
    /* 新字符串 */
    if (g_dr.needle_count < DR_MAX_CAPTURED_STRINGS) {
        struct captured_needle *n = &g_dr.needles[g_dr.needle_count];
        memcpy(n->value, str, len);
        n->value[len] = '\0';
        n->len = len;
        n->found_at = found_at;
        n->found_via_reg = found_via_reg;
        n->pc_when_found = pc;
        n->lr_when_found = lr;
        n->tid_when_found = current->pid;
        memcpy(n->comm, current->comm, 16);
        n->syscall_nr = syscall_nr;
        n->hit_count = 1;
        n->first_seen_ns = ktime_get_ns();
        n->last_seen_ns = n->first_seen_ns;
        g_dr.needle_count++;
        g_dr.stat_new_needles++;
    }
    dr_unlock();
}

/*
 * ★★★ 核心函数 ★★★
 * 
 * 在 syscall hook 中调用
 * 扫描当前所有寄存器, 如果寄存器值看起来是用户态指针,
 * 就去解引用, 看指向的内容是不是字符串
 * 
 * 原理:
 *   壳自己的 memmem(haystack, needle) 在调用期间,
 *   needle 的地址一定在某个寄存器里 (比如 x1, 或者被 callee-save 到栈上)
 *   
 *   壳的检测线程在执行 syscall 时 (比如 read maps, 或者结果判断后 kill),
 *   这些寄存器可能还保持着之前比对函数的上下文
 *   
 *   我们遍历所有寄存器和栈上的值, 提取字符串,
 *   配合多次采样, 就能还原出壳在检测什么
 */
void dr_capture_context(struct pt_regs *regs, int syscall_nr)
{
    int i;
    char str_buf[DR_MAX_STR_LEN];
    int str_len;
    struct context_dump *dump = NULL;
    
    if (!is_target_thread())
        return;
    
    g_dr.stat_syscalls_scanned++;
    
    /* 分配上下文 dump (如果开启) */
    if (g_dr.dump_full_context && g_dr.dumps && g_dr.dump_count < g_dr.dump_max) {
        dump = &g_dr.dumps[g_dr.dump_count];
        memset(dump, 0, sizeof(*dump));
        dump->timestamp_ns = ktime_get_ns();
        dump->pid = current->tgid;
        dump->tid = current->pid;
        memcpy(dump->comm, current->comm, 16);
        dump->syscall_nr = syscall_nr;
        dump->pc = regs->pc;
        dump->sp = regs->sp;
        dump->lr = regs->regs[30];
    }
    
    /* ── 扫描 x0 - x28 ── */
    for (i = 0; i <= 28; i++) {
        unsigned long val = regs->regs[i];
        g_dr.stat_regs_derefed++;
        
        if (!is_user_addr(val))
            continue;
        
        str_len = extract_string(val, str_buf, sizeof(str_buf));
        
        if (dump) {
            dump->regs[i] = val;
            dump->reg_deref[i].addr = val;
            dump->reg_deref[i].valid = 1;
            safe_read_user(val, dump->reg_deref[i].content, 64);
            if (str_len > 0) {
                dump->reg_deref[i].is_string = 1;
                memcpy(dump->reg_deref[i].string_val, str_buf, 
                       str_len < 127 ? str_len + 1 : 128);
            }
        }
        
        if (str_len > 0) {
            g_dr.stat_strings_found++;
            add_needle(str_buf, str_len, val, i, regs->pc, regs->regs[30], syscall_nr);
        }
        
        /* 二级解引用: 寄存器指向的是一个指针数组? */
        /* 壳可能用 const char *detect_strings[] = {"frida", "gum-js", ...}; */
        {
            unsigned long ptr_val;
            int j;
            for (j = 0; j < 16; j++) {  /* 最多看16个指针 */
                if (safe_read_user(val + j * 8, (char *)&ptr_val, 8) != 0)
                    break;
                if (!is_user_addr(ptr_val))
                    continue;
                str_len = extract_string(ptr_val, str_buf, sizeof(str_buf));
                if (str_len > 0) {
                    g_dr.stat_strings_found++;
                    add_needle(str_buf, str_len, ptr_val, i + 100,
                              regs->pc, regs->regs[30], syscall_nr);
                }
                /* 遇到 NULL 指针就是数组结束 */
                if (ptr_val == 0)
                    break;
            }
        }
    }
    
    /* ── 扫描 LR (x30) ── */
    /* LR 通常是代码地址, 但如果 LR 被破坏或复用, 也看看 */
    
    /* ── 扫描栈 ── */
    if (g_dr.scan_stack && regs->sp) {
        unsigned long sp = regs->sp;
        int stack_str_idx = 0;
        unsigned long stack_val;
        int offset;
        
        for (offset = 0; offset < DR_STACK_SCAN_DEPTH && stack_str_idx < 32; offset += 8) {
            if (safe_read_user(sp + offset, (char *)&stack_val, 8) != 0)
                break;
            
            if (!is_user_addr(stack_val))
                continue;
            
            str_len = extract_string(stack_val, str_buf, sizeof(str_buf));
            if (str_len > 0) {
                g_dr.stat_strings_found++;
                add_needle(str_buf, str_len, stack_val, 99,  /* 99 = from stack */
                          regs->pc, regs->regs[30], syscall_nr);
                
                if (dump && stack_str_idx < 32) {
                    dump->stack_strings[stack_str_idx].stack_offset = offset;
                    dump->stack_strings[stack_str_idx].ptr_value = stack_val;
                    memcpy(dump->stack_strings[stack_str_idx].string_val, 
                           str_buf, str_len < 127 ? str_len + 1 : 128);
                    stack_str_idx++;
                }
            }
        }
        
        if (dump) {
            dump->stack_string_count = stack_str_idx;
        }
    }
    
    if (dump) {
        g_dr.dump_count++;
    }
}

/*
 * 在 sys_read 的返回 hook 中调用
 * 此时检测线程刚读完 maps 或内存块,
 * 寄存器和栈上很可能还有 needle 的残留
 */
void dr_on_read_exit(struct pt_regs *regs, int fd, ssize_t ret)
{
    if (!g_dr.capture_on_read || !is_target_thread())
        return;
    
    /* 只在读 maps 或 较小 buffer 时触发 (减少噪声) */
    /* TODO: 可以加 fd 类型判断 */
    
    dr_capture_context(regs, 63);  /* read = 63 */
}

/*
 * 在 sys_openat 中调用
 * 检测线程打开 /proc/self/maps 时, 正在准备扫描
 */
void dr_on_openat(struct pt_regs *regs, const char __user *filename)
{
    char kpath[64];
    
    if (!g_dr.capture_on_openat || !is_target_thread())
        return;
    
    if (strncpy_from_user(kpath, filename, sizeof(kpath) - 1) <= 0)
        return;
    kpath[sizeof(kpath) - 1] = '\0';
    
    /* 只在打开 proc 文件时触发 */
    if (strstr(kpath, "/proc/"))
        dr_capture_context(regs, 56);  /* openat = 56 */
}

/*
 * 在 sys_kill / sys_exit_group 中调用
 * ★ 这是最有价值的时机 ★
 * 壳做完检测, 准备杀进程的瞬间,
 * 栈上很可能还有检测函数的完整上下文
 */
void dr_on_kill_exit(struct pt_regs *regs, int sig)
{
    if (!g_dr.capture_on_kill || !is_target_thread())
        return;
    
    /* SIGKILL = 壳准备杀进程, 这是最关键的时刻 */
    if (sig == 9 || sig == 6) {  /* SIGKILL or SIGABRT */
        dr_capture_context(regs, 129);  /* kill = 129 */
    }
}

/*
 * 在 sys_exit_group 中调用
 */
void dr_on_exit_group(struct pt_regs *regs)
{
    if (!g_dr.capture_on_kill || !is_target_thread())
        return;
    dr_capture_context(regs, 94);  /* exit_group = 94 */
}

/* ═══════════════════════════════════════════════
 * CTL 命令接口
 * ═══════════════════════════════════════════════ */

/*
 * 命令:
 *   dr_enable <pid>               启用, 指定目标 PID
 *   dr_disable                    禁用
 *   dr_add_tid <tid>              添加目标线程 (检测线程)
 *   dr_capture_all                捕获所有线程 (不限 TID)
 *   dr_config <key> <value>       配置 (read|kill|openat|stack|fulldump = on|off)
 *   dr_needles                    ★ 查看捕获到的字符串 ★
 *   dr_dump <index>               查看完整上下文 dump
 *   dr_clear                      清空
 *   dr_status                     状态
 */
int dr_handle_ctl(const char *cmd, char *output, int output_size)
{
    int n = 0;
    
    if (strncmp(cmd, "dr_enable", 9) == 0) {
        const char *p = cmd + 9;
        long pid_val = 0;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { pid_val = pid_val * 10 + (*p - '0'); p++; }
        
        g_dr.target_pid = (pid_t)pid_val;
        g_dr.enabled = 1;
        g_dr.capture_on_read = 1;
        g_dr.capture_on_kill = 1;
        g_dr.capture_on_openat = 1;
        g_dr.scan_stack = 1;
        g_dr.capture_all_threads = 1;  /* 默认捕获所有线程 */
        
        return snprintf(output, output_size,
            "detect_reverser: ENABLED pid=%d (read=%d kill=%d openat=%d stack=%d)\n",
            g_dr.target_pid, g_dr.capture_on_read, g_dr.capture_on_kill,
            g_dr.capture_on_openat, g_dr.scan_stack);
    }
    
    if (strcmp(cmd, "dr_disable") == 0) {
        g_dr.enabled = 0;
        return snprintf(output, output_size, "detect_reverser: DISABLED\n");
    }
    
    if (strncmp(cmd, "dr_add_tid", 10) == 0) {
        const char *p = cmd + 10;
        long tid_val = 0;
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') { tid_val = tid_val * 10 + (*p - '0'); p++; }
        
        if (g_dr.target_tid_count < 16) {
            g_dr.target_tids[g_dr.target_tid_count++] = (pid_t)tid_val;
            g_dr.capture_all_threads = 0;
            return snprintf(output, output_size,
                "detect_reverser: added TID %ld (total %d)\n",
                tid_val, g_dr.target_tid_count);
        }
        return snprintf(output, output_size, "detect_reverser: TID list full\n");
    }
    
    if (strcmp(cmd, "dr_capture_all") == 0) {
        g_dr.capture_all_threads = 1;
        return snprintf(output, output_size, "detect_reverser: capture ALL threads\n");
    }
    
    if (strncmp(cmd, "dr_config ", 10) == 0) {
        const char *p = cmd + 10;
        if (strncmp(p, "read ", 5) == 0) {
            g_dr.capture_on_read = (strstr(p+5, "on") != NULL);
        } else if (strncmp(p, "kill ", 5) == 0) {
            g_dr.capture_on_kill = (strstr(p+5, "on") != NULL);
        } else if (strncmp(p, "openat ", 7) == 0) {
            g_dr.capture_on_openat = (strstr(p+7, "on") != NULL);
        } else if (strncmp(p, "stack ", 6) == 0) {
            g_dr.scan_stack = (strstr(p+6, "on") != NULL);
        } else if (strncmp(p, "fulldump ", 9) == 0) {
            g_dr.dump_full_context = (strstr(p+9, "on") != NULL);
        }
        return snprintf(output, output_size,
            "detect_reverser: read=%d kill=%d openat=%d stack=%d fulldump=%d\n",
            g_dr.capture_on_read, g_dr.capture_on_kill,
            g_dr.capture_on_openat, g_dr.scan_stack, g_dr.dump_full_context);
    }
    
    /* ★★★ 最重要的命令: 查看捕获到的 needles ★★★ */
    if (strcmp(cmd, "dr_needles") == 0) {
        n += snprintf(output + n, output_size - n,
            "=== Captured Detection Strings (%d unique) ===\n"
            "These are strings the shell's detection function was comparing against:\n\n",
            g_dr.needle_count);
        
        int i;
        for (i = 0; i < g_dr.needle_count && n < output_size - 256; i++) {
            struct captured_needle *nd = &g_dr.needles[i];
            
            const char *source;
            if (nd->found_via_reg <= 28)
                source = "register";
            else if (nd->found_via_reg >= 100 && nd->found_via_reg < 200)
                source = "ptr_array";
            else
                source = "stack";
            
            n += snprintf(output + n, output_size - n,
                "  [%d] \"%s\"\n"
                "      hits=%d  found_via=%s(x%lu)  addr=0x%lx\n"
                "      pc=0x%lx  lr=0x%lx  tid=%d  comm=%s  nr=%d\n\n",
                i, nd->value,
                nd->hit_count,
                source,
                nd->found_via_reg < 100 ? nd->found_via_reg : nd->found_via_reg - 100,
                nd->found_at,
                nd->pc_when_found,
                nd->lr_when_found,
                nd->tid_when_found,
                nd->comm,
                nd->syscall_nr);
        }
        
        if (g_dr.needle_count == 0) {
            n += snprintf(output + n, output_size - n,
                "  (none captured yet - make sure target app is running)\n");
        }
        return n;
    }
    
    if (strcmp(cmd, "dr_status") == 0) {
        n += snprintf(output + n, output_size - n,
            "=== Detection Reverser Status ===\n"
            "enabled: %d\n"
            "target_pid: %d\n"
            "target_tids: %d (capture_all=%d)\n"
            "capture: read=%d kill=%d openat=%d\n"
            "scan_stack: %d\n"
            "dump_full_context: %d\n"
            "--- Results ---\n"
            "unique_needles: %d\n"
            "context_dumps: %d\n"
            "--- Stats ---\n"
            "syscalls_scanned: %lu\n"
            "regs_derefed: %lu\n"
            "strings_found: %lu\n"
            "new_needles: %lu\n",
            g_dr.enabled, g_dr.target_pid,
            g_dr.target_tid_count, g_dr.capture_all_threads,
            g_dr.capture_on_read, g_dr.capture_on_kill, g_dr.capture_on_openat,
            g_dr.scan_stack, g_dr.dump_full_context,
            g_dr.needle_count, g_dr.dump_count,
            g_dr.stat_syscalls_scanned, g_dr.stat_regs_derefed,
            g_dr.stat_strings_found, g_dr.stat_new_needles);
        return n;
    }
    
    if (strcmp(cmd, "dr_clear") == 0) {
        dr_lock();
        g_dr.needle_count = 0;
        g_dr.dump_count = 0;
        g_dr.stat_syscalls_scanned = 0;
        g_dr.stat_regs_derefed = 0;
        g_dr.stat_strings_found = 0;
        g_dr.stat_new_needles = 0;
        dr_unlock();
        return snprintf(output, output_size, "detect_reverser: cleared\n");
    }
    
    /* dump 特定上下文 */
    if (strncmp(cmd, "dr_dump ", 8) == 0) {
        long idx = 0;
        const char *p = cmd + 8;
        while (*p >= '0' && *p <= '9') { idx = idx * 10 + (*p - '0'); p++; }
        
        if (!g_dr.dumps || idx >= g_dr.dump_count) {
            return snprintf(output, output_size,
                "detect_reverser: dump index %ld out of range (have %d)\n",
                idx, g_dr.dump_count);
        }
        
        struct context_dump *d = &g_dr.dumps[idx];
        n += snprintf(output + n, output_size - n,
            "=== Context Dump #%ld ===\n"
            "time=%lu pid=%d tid=%d comm=%s nr=%d\n"
            "pc=0x%lx sp=0x%lx lr=0x%lx\n"
            "--- Registers with strings ---\n",
            idx, d->timestamp_ns / 1000000, d->pid, d->tid, d->comm, d->syscall_nr,
            d->pc, d->sp, d->lr);
        
        int i;
        for (i = 0; i <= 28 && n < output_size - 200; i++) {
            if (d->reg_deref[i].is_string) {
                n += snprintf(output + n, output_size - n,
                    "  x%d = 0x%lx → \"%s\"\n",
                    i, d->reg_deref[i].addr, d->reg_deref[i].string_val);
            }
        }
        
        if (d->stack_string_count > 0) {
            n += snprintf(output + n, output_size - n,
                "--- Stack strings ---\n");
            for (i = 0; i < d->stack_string_count && n < output_size - 200; i++) {
                n += snprintf(output + n, output_size - n,
                    "  [sp+0x%lx] → 0x%lx → \"%s\"\n",
                    d->stack_strings[i].stack_offset,
                    d->stack_strings[i].ptr_value,
                    d->stack_strings[i].string_val);
            }
        }
        return n;
    }
    
    return -1;  /* 未识别 */
}

/* ═══════════════════════════════════════════════
 * Init / Exit
 * ═══════════════════════════════════════════════ */

int dr_init(void)
{
    memset(&g_dr, 0, sizeof(g_dr));
    
    /* 分配上下文 dump 空间 */
    g_dr.dump_max = DR_MAX_DUMP_ENTRIES;
    g_dr.dumps = vmalloc(sizeof(struct context_dump) * g_dr.dump_max);
    if (g_dr.dumps)
        memset(g_dr.dumps, 0, sizeof(struct context_dump) * g_dr.dump_max);
    
    printk(KERN_INFO "detect_reverser: initialized (%d needle slots, %d dump slots)\n",
           DR_MAX_CAPTURED_STRINGS, g_dr.dump_max);
    return 0;
}

void dr_exit(void)
{
    g_dr.enabled = 0;
    if (g_dr.dumps) {
        vfree(g_dr.dumps);
        g_dr.dumps = NULL;
    }
    printk(KERN_INFO "detect_reverser: cleaned up (found %d unique needles)\n",
           g_dr.needle_count);
}
