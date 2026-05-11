/**
 * mem_monitor.c — KPM Memory Access Monitor Extension
 * 
 * 用于检测和对抗壳自实现的字符串搜索函数
 * 
 * 核心功能:
 * 1. read() syscall 内容监控 — 看检测函数读了什么
 * 2. /proc/self/maps 读取拦截 — 知道检测函数什么时候在扫描内存布局
 * 3. 字符串匹配监控 — 在内核层面看检测函数在搜什么字符串
 * 4. 可选: maps 内容过滤 — 隐藏敏感映射行
 * 
 * 思路:
 *   壳自己写的 memmem/strstr 替代函数，最终还是要通过 syscall 来:
 *   (1) 读 /proc/self/maps 获取内存区域列表
 *   (2) 用 read() 或直接用户态指针遍历内存
 *   (3) 逐字节比对目标字符串
 *   
 *   在内核层面，我们可以:
 *   - hook sys_read，当 fd 指向 /proc/self/maps 时记录调用者 PC
 *   - hook sys_read 的返回，检查读到的 buffer 里有没有敏感关键词
 *   - hook sys_openat，记录谁打开了 maps 文件
 *   - 结合 do_filp_open hook，精确追踪文件访问
 * 
 * 编译: 作为 svc_monitor.c 的扩展模块或直接合并
 * 目标: Pixel 6 / ARM64 / Android 12 / kernel 5.10.43
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

/* ═══════════════════════════════════════════════
 * 配置常量
 * ═══════════════════════════════════════════════ */

#define MEM_MON_MAX_WATCH_STRINGS  32    /* 最多同时监控32个字符串 */
#define MEM_MON_MAX_STR_LEN        128   /* 单个监控字符串最大长度 */
#define MEM_MON_MAX_LOG_ENTRIES    4096  /* 日志缓冲区条目数 */
#define MEM_MON_READ_SCAN_MAX     4096  /* read buffer 最大扫描字节数 */

/* ═══════════════════════════════════════════════
 * 数据结构
 * ═══════════════════════════════════════════════ */

/* 监控的目标字符串 */
struct watch_string {
    char value[MEM_MON_MAX_STR_LEN];
    int  len;
    int  active;
    unsigned long hit_count;  /* 命中次数 */
};

/* 内存访问日志条目 */
struct mem_access_log {
    unsigned long timestamp_ns;   /* ktime_get_ns() */
    pid_t pid;
    pid_t tid;
    char comm[16];
    unsigned long pc;            /* 调用者 PC（从 syscall 入口的寄存器拿） */
    unsigned long lr;            /* 调用者 LR */
    unsigned long caller_fp;     /* frame pointer */
    int syscall_nr;              /* 触发的 syscall 号 */
    int event_type;              /* 见下方枚举 */
    /* 事件相关数据 */
    union {
        struct {
            int fd;
            unsigned long buf_addr;    /* 用户态 buffer 地址 */
            size_t count;              /* 请求读取的大小 */
            ssize_t ret;               /* 实际读取的大小 */
            int matched_str_idx;       /* 匹配到的字符串索引, -1=无 */
            char matched_context[64];  /* 匹配位置附近的内容 */
        } read_event;
        struct {
            char pathname[128];        /* 打开的文件路径 */
            int flags;
            int fd_result;
        } open_event;
        struct {
            unsigned long addr;        /* 被访问的地址 */
            int matched_str_idx;
            char matched_context[64];
        } mem_scan_event;
    } data;
};

enum mem_event_type {
    MEM_EVT_MAPS_OPEN    = 1,  /* 打开 /proc/xxx/maps */
    MEM_EVT_MAPS_READ    = 2,  /* 读取 maps 内容 */
    MEM_EVT_READ_MATCH   = 3,  /* read() buffer 中发现监控字符串 */
    MEM_EVT_MEM_SCAN     = 4,  /* 检测到内存扫描模式 */
    MEM_EVT_PROC_OPEN    = 5,  /* 打开 /proc 下其他文件 (status/cmdline等) */
    MEM_EVT_SUSPICIOUS   = 6,  /* 可疑行为 (大量连续 read, mmap 扫描等) */
};

/* ═══════════════════════════════════════════════
 * 全局状态
 * ═══════════════════════════════════════════════ */

static struct {
    /* 监控开关 */
    int enabled;
    pid_t target_uid;          /* 目标 UID, 0=不限 */
    pid_t target_pid;          /* 目标 PID, 0=不限 */
    
    /* 监控字符串列表 */
    struct watch_string watch_strings[MEM_MON_MAX_WATCH_STRINGS];
    int watch_count;
    
    /* 日志环形缓冲区 */
    struct mem_access_log *log_buf;
    unsigned long log_head;    /* 写位置 */
    unsigned long log_tail;    /* 读位置 */
    unsigned long log_total;   /* 总记录数 */
    
    /* maps 文件 fd 追踪 (per-thread, 简化为全局数组) */
    struct {
        pid_t tid;
        int fd;
    } maps_fds[64];
    int maps_fd_count;
    
    /* 统计 */
    unsigned long stat_maps_opens;
    unsigned long stat_maps_reads;
    unsigned long stat_string_hits;
    unsigned long stat_suspicious;
    
    /* 自旋锁 */
    /* 使用 ARM64 原子操作, 与你现有的 svc_monitor 一致 */
    volatile int lock;
    
} g_mem_mon;

/* ═══════════════════════════════════════════════
 * ARM64 Spinlock (与 svc_monitor.c 一致)
 * ═══════════════════════════════════════════════ */

static inline void mem_mon_lock(void)
{
    int tmp;
    asm volatile(
        "1: ldaxr %w0, [%1]\n"
        "   cbnz  %w0, 1b\n"
        "   mov   %w0, #1\n"
        "   stxr  %w0, %w0, [%1]\n"
        "   cbnz  %w0, 1b\n"
        : "=&r"(tmp)
        : "r"(&g_mem_mon.lock)
        : "memory"
    );
}

static inline void mem_mon_unlock(void)
{
    asm volatile(
        "stlr wzr, [%0]\n"
        :
        : "r"(&g_mem_mon.lock)
        : "memory"
    );
}

/* ═══════════════════════════════════════════════
 * 日志记录
 * ═══════════════════════════════════════════════ */

static void mem_mon_log(struct mem_access_log *entry)
{
    if (!g_mem_mon.log_buf)
        return;
    
    entry->timestamp_ns = ktime_get_ns();
    entry->pid = current->tgid;
    entry->tid = current->pid;
    memcpy(entry->comm, current->comm, 16);
    
    mem_mon_lock();
    unsigned long idx = g_mem_mon.log_head % MEM_MON_MAX_LOG_ENTRIES;
    memcpy(&g_mem_mon.log_buf[idx], entry, sizeof(*entry));
    g_mem_mon.log_head++;
    g_mem_mon.log_total++;
    mem_mon_unlock();
}

/* ═══════════════════════════════════════════════
 * 字符串匹配引擎
 * ═══════════════════════════════════════════════ */

/*
 * 在用户态 buffer 中搜索所有监控字符串
 * 返回: 匹配到的字符串索引, -1=无匹配
 * context_out: 如果匹配到, 拷贝匹配位置附近的内容
 */
static int scan_buffer_for_watch_strings(
    const char __user *ubuf, 
    size_t len,
    char *context_out, 
    int context_size)
{
    char *kbuf;
    int i, found = -1;
    size_t scan_len;
    
    if (!ubuf || !len || !g_mem_mon.watch_count)
        return -1;
    
    /* 限制扫描大小, 避免大量内核内存分配 */
    scan_len = len > MEM_MON_READ_SCAN_MAX ? MEM_MON_READ_SCAN_MAX : len;
    
    kbuf = kmalloc(scan_len + 1, GFP_ATOMIC);
    if (!kbuf)
        return -1;
    
    if (copy_from_user(kbuf, ubuf, scan_len)) {
        kfree(kbuf);
        return -1;
    }
    kbuf[scan_len] = '\0';
    
    /* 逐个检查监控字符串 */
    for (i = 0; i < MEM_MON_MAX_WATCH_STRINGS; i++) {
        if (!g_mem_mon.watch_strings[i].active)
            continue;
        
        char *match = strnstr(kbuf, g_mem_mon.watch_strings[i].value, scan_len);
        if (match) {
            found = i;
            g_mem_mon.watch_strings[i].hit_count++;
            g_mem_mon.stat_string_hits++;
            
            /* 提取上下文: 匹配位置前后各取一些 */
            if (context_out && context_size > 0) {
                int offset = (int)(match - kbuf);
                int ctx_start = offset > 16 ? offset - 16 : 0;
                int ctx_end = offset + g_mem_mon.watch_strings[i].len + 16;
                if (ctx_end > (int)scan_len) ctx_end = (int)scan_len;
                int ctx_len = ctx_end - ctx_start;
                if (ctx_len > context_size - 1) ctx_len = context_size - 1;
                memcpy(context_out, kbuf + ctx_start, ctx_len);
                context_out[ctx_len] = '\0';
            }
            break;  /* 找到第一个就够了 */
        }
    }
    
    kfree(kbuf);
    return found;
}

/* ═══════════════════════════════════════════════
 * 检查是否为 maps 文件的 fd
 * ═══════════════════════════════════════════════ */

static int is_maps_fd(int fd)
{
    struct file *f;
    char buf[64];
    char *path;
    
    f = fget(fd);
    if (!f)
        return 0;
    
    path = d_path(&f->f_path, buf, sizeof(buf));
    fput(f);
    
    if (IS_ERR(path))
        return 0;
    
    /* 检查是不是 /proc/xxx/maps 或 /proc/self/maps */
    if (strstr(path, "/maps") && strstr(path, "/proc/"))
        return 1;
    
    return 0;
}

/* 检查是否为 /proc/ 下的敏感文件 */
static int check_proc_file_type(const char *path)
{
    if (!path)
        return 0;
    if (strstr(path, "/proc/") == NULL)
        return 0;
    
    if (strstr(path, "/maps"))     return MEM_EVT_MAPS_OPEN;
    if (strstr(path, "/status"))   return MEM_EVT_PROC_OPEN;
    if (strstr(path, "/cmdline"))  return MEM_EVT_PROC_OPEN;
    if (strstr(path, "/stat"))     return MEM_EVT_PROC_OPEN;
    if (strstr(path, "/fd"))       return MEM_EVT_PROC_OPEN;
    if (strstr(path, "/mem"))      return MEM_EVT_PROC_OPEN;
    if (strstr(path, "/task"))     return MEM_EVT_PROC_OPEN;
    if (strstr(path, "/mountinfo"))return MEM_EVT_PROC_OPEN;
    
    return 0;
}

/* ═══════════════════════════════════════════════
 * Syscall Hook Handlers
 * 这些函数从你现有的 svc_monitor 的 hook 框架调用
 * ═══════════════════════════════════════════════ */

/*
 * 方案1: 在 sys_openat 的 hook 中调用
 * 检测谁在打开 /proc/xxx/maps
 */
void mem_mon_on_openat(
    int dfd, 
    const char __user *filename, 
    int flags,
    unsigned long pc,
    unsigned long lr)
{
    char kpath[128];
    struct mem_access_log entry = {0};
    int file_type;
    
    if (!g_mem_mon.enabled)
        return;
    
    /* 目标过滤 */
    if (g_mem_mon.target_pid && current->tgid != g_mem_mon.target_pid)
        return;
    
    /* 拷贝文件名 */
    if (strncpy_from_user(kpath, filename, sizeof(kpath) - 1) <= 0)
        return;
    kpath[sizeof(kpath) - 1] = '\0';
    
    file_type = check_proc_file_type(kpath);
    if (!file_type)
        return;
    
    /* 记录日志 */
    entry.event_type = file_type;
    entry.pc = pc;
    entry.lr = lr;
    entry.syscall_nr = 56;  /* openat */
    strncpy(entry.data.open_event.pathname, kpath, 
            sizeof(entry.data.open_event.pathname) - 1);
    entry.data.open_event.flags = flags;
    
    mem_mon_log(&entry);
    
    if (file_type == MEM_EVT_MAPS_OPEN) {
        g_mem_mon.stat_maps_opens++;
        /* 后续跟踪这个 fd, 在 openat 返回后设置 */
    }
}

/*
 * 方案2: 在 sys_openat 返回时调用
 * 记录 maps 文件的 fd, 方便后续 read 追踪
 */
void mem_mon_on_openat_ret(const char __user *filename, int fd_ret)
{
    char kpath[128];
    
    if (!g_mem_mon.enabled || fd_ret < 0)
        return;
    
    if (strncpy_from_user(kpath, filename, sizeof(kpath) - 1) <= 0)
        return;
    kpath[sizeof(kpath) - 1] = '\0';
    
    if (strstr(kpath, "/proc/") && strstr(kpath, "/maps")) {
        /* 记录这个 tid+fd 组合 */
        mem_mon_lock();
        if (g_mem_mon.maps_fd_count < 64) {
            g_mem_mon.maps_fds[g_mem_mon.maps_fd_count].tid = current->pid;
            g_mem_mon.maps_fds[g_mem_mon.maps_fd_count].fd = fd_ret;
            g_mem_mon.maps_fd_count++;
        }
        mem_mon_unlock();
    }
}

/*
 * 方案3: 在 sys_read 的 hook 中调用 (核心!)
 * 
 * 这是最关键的 — 壳的自实现 strstr 最终还是要通过 read() 
 * 来读取内存区域的内容。我们在 read 返回后扫描 buffer,
 * 看看它读到了什么。
 * 
 * 调用时机: sys_read 返回后 (需要看到实际读到的数据)
 */
void mem_mon_on_read_ret(
    int fd,
    char __user *buf,
    size_t count,
    ssize_t ret,     /* 实际读取的字节数 */
    unsigned long pc,
    unsigned long lr)
{
    struct mem_access_log entry = {0};
    int is_maps = 0;
    int match_idx;
    
    if (!g_mem_mon.enabled || ret <= 0)
        return;
    
    /* 目标过滤 */
    if (g_mem_mon.target_pid && current->tgid != g_mem_mon.target_pid)
        return;
    
    /* 检查是不是在读 maps 文件 */
    is_maps = is_maps_fd(fd);
    
    if (is_maps) {
        /* maps 读取事件 */
        g_mem_mon.stat_maps_reads++;
        
        entry.event_type = MEM_EVT_MAPS_READ;
        entry.pc = pc;
        entry.lr = lr;
        entry.syscall_nr = 63;  /* read */
        entry.data.read_event.fd = fd;
        entry.data.read_event.buf_addr = (unsigned long)buf;
        entry.data.read_event.count = count;
        entry.data.read_event.ret = ret;
        entry.data.read_event.matched_str_idx = -1;
        
        /* 扫描 maps 内容, 看有没有我们关心的字符串 */
        match_idx = scan_buffer_for_watch_strings(
            buf, (size_t)ret,
            entry.data.read_event.matched_context,
            sizeof(entry.data.read_event.matched_context));
        entry.data.read_event.matched_str_idx = match_idx;
        
        mem_mon_log(&entry);
        return;
    }
    
    /* 对于非 maps 的 read, 也扫描 buffer 看有没有目标字符串 */
    /* 但只在 buffer 较小时做(避免性能问题) */
    if (ret <= MEM_MON_READ_SCAN_MAX) {
        match_idx = scan_buffer_for_watch_strings(
            buf, (size_t)ret,
            entry.data.read_event.matched_context,
            sizeof(entry.data.read_event.matched_context));
        
        if (match_idx >= 0) {
            entry.event_type = MEM_EVT_READ_MATCH;
            entry.pc = pc;
            entry.lr = lr;
            entry.syscall_nr = 63;
            entry.data.read_event.fd = fd;
            entry.data.read_event.buf_addr = (unsigned long)buf;
            entry.data.read_event.count = count;
            entry.data.read_event.ret = ret;
            entry.data.read_event.matched_str_idx = match_idx;
            
            mem_mon_log(&entry);
        }
    }
}

/*
 * 方案4: 高级 — 拦截 process_vm_readv / ptrace PEEK
 * 有些壳会用 process_vm_readv 来读自己的内存
 */
void mem_mon_on_process_vm_readv(
    pid_t pid_target,
    unsigned long remote_iov_addr,
    unsigned long local_iov_addr,
    unsigned long pc,
    unsigned long lr)
{
    struct mem_access_log entry = {0};
    
    if (!g_mem_mon.enabled)
        return;
    if (g_mem_mon.target_pid && current->tgid != g_mem_mon.target_pid)
        return;
    
    /* process_vm_readv 读自己的内存 = 可疑的内存扫描行为 */
    if (pid_target == current->tgid || pid_target == current->pid) {
        g_mem_mon.stat_suspicious++;
        
        entry.event_type = MEM_EVT_SUSPICIOUS;
        entry.pc = pc;
        entry.lr = lr;
        entry.syscall_nr = 270;  /* process_vm_readv */
        
        mem_mon_log(&entry);
    }
}

/* ═══════════════════════════════════════════════
 * Maps 内容过滤 (可选, 主动防御)
 * 
 * 在 sys_read 返回给用户态之前, 修改 buffer 内容
 * 把包含敏感关键词的行替换掉
 * ═══════════════════════════════════════════════ */

/* 需要隐藏的 maps 行中的关键词 */
static const char *maps_filter_keywords[] = {
    "frida",
    "gum-js",
    "linjector",
    "gadget",
    "re.frida.server",
    /* 按需添加 */
    NULL
};

/*
 * 在 read() 返回前, 如果读的是 maps, 过滤掉敏感行
 * 注意: 这个功能是可选的, 默认关闭
 * 开启后能直接让壳的检测失效
 */
static int g_maps_filter_enabled = 0;

void mem_mon_filter_maps_content(char __user *buf, ssize_t *ret_size)
{
    char *kbuf, *out, *line, *next;
    ssize_t orig_size, new_size;
    int i, should_filter;
    
    if (!g_maps_filter_enabled || !buf || !ret_size || *ret_size <= 0)
        return;
    
    orig_size = *ret_size;
    kbuf = kmalloc(orig_size + 1, GFP_ATOMIC);
    if (!kbuf)
        return;
    
    if (copy_from_user(kbuf, buf, orig_size)) {
        kfree(kbuf);
        return;
    }
    kbuf[orig_size] = '\0';
    
    /* 分配输出缓冲区 */
    out = kmalloc(orig_size + 1, GFP_ATOMIC);
    if (!out) {
        kfree(kbuf);
        return;
    }
    
    new_size = 0;
    line = kbuf;
    
    while (line && *line) {
        next = strchr(line, '\n');
        if (next) *next = '\0';
        
        /* 检查这一行是否包含需要过滤的关键词 */
        should_filter = 0;
        for (i = 0; maps_filter_keywords[i]; i++) {
            if (strstr(line, maps_filter_keywords[i])) {
                should_filter = 1;
                break;
            }
        }
        
        if (!should_filter) {
            int line_len = strlen(line);
            memcpy(out + new_size, line, line_len);
            new_size += line_len;
            out[new_size++] = '\n';
        }
        
        line = next ? next + 1 : NULL;
    }
    
    /* 写回用户态 */
    if (new_size != orig_size) {
        if (!copy_to_user(buf, out, new_size)) {
            *ret_size = new_size;
        }
    }
    
    kfree(kbuf);
    kfree(out);
}

/* ═══════════════════════════════════════════════
 * 高级方案: 用户态内存页监控
 * 
 * 通过修改页表项将目标页设为不可读,
 * 当检测函数访问这些页时触发 page fault,
 * 我们在 fault handler 中记录访问者信息
 * 
 * 这个方案可以精确知道"谁在读哪块内存",
 * 但实现复杂度较高, 这里给出框架
 * ═══════════════════════════════════════════════ */

struct page_trap_entry {
    unsigned long addr;        /* 被监控的页面地址 (页对齐) */
    unsigned long orig_pte;    /* 原始 PTE 值 */
    int active;
    unsigned long hit_count;
};

#define MAX_PAGE_TRAPS 16
static struct page_trap_entry g_page_traps[MAX_PAGE_TRAPS];

/*
 * 设置页面陷阱
 * 将目标地址所在的页标记为不可读
 * 当有人访问时, fault handler 会被调用
 * 
 * 注意: 这个需要操作目标进程的页表, 实现较复杂
 * 这里提供接口框架, 具体的页表操作需要根据内核版本适配
 */
int mem_mon_set_page_trap(unsigned long addr)
{
    /* TODO: 实际实现需要:
     * 1. 找到目标进程的 mm_struct
     * 2. walk page table 找到对应的 PTE
     * 3. 保存原始 PTE
     * 4. 清除 PTE_READ 位
     * 5. flush TLB
     * 
     * 在 page fault handler 中:
     * 1. 检查是不是我们设置的 trap
     * 2. 记录访问者的 PC, 寄存器等信息
     * 3. 恢复 PTE
     * 4. 设置单步, 执行完后重新设置 trap
     */
    return -1;  /* 暂未实现 */
}

/* ═══════════════════════════════════════════════
 * CTL 接口 (通过 KPM 的 ctl 机制控制)
 * ═══════════════════════════════════════════════ */

/*
 * 命令格式 (通过 svc_monitor 的 CTL 扩展):
 *   mem_mon_enable [pid]          - 启用内存监控
 *   mem_mon_disable               - 禁用
 *   mem_mon_watch <string>        - 添加监控字符串
 *   mem_mon_unwatch <string>      - 移除
 *   mem_mon_unwatch_all           - 清空所有
 *   mem_mon_preset_frida          - 预设 Frida 相关字符串
 *   mem_mon_preset_xjd            - 预设 xjd-cache 相关
 *   mem_mon_maps_filter <on|off>  - maps 过滤开关
 *   mem_mon_status                - 查看状态
 *   mem_mon_dump                  - 导出日志
 *   mem_mon_clear                 - 清空日志
 */

/* 预设: Frida 检测常用字符串 */
static const char *PRESET_FRIDA[] = {
    "frida",
    "LIBFRIDA",
    "gum-js-loop",
    "gmain",
    "linjector",
    "frida-agent",
    "frida_agent",
    "re.frida.server",
    "frida-server",
    "/data/local/tmp/frida",
    "27042",          /* Frida 默认端口 */
    "gadget",
    "frida-gadget",
    NULL
};

/* 预设: xjd-cache / 壳相关字符串 */
static const char *PRESET_XJD[] = {
    "xjd-cache",
    "libexec.so",
    "libDexHelper",
    "dex2oat",
    "frida",
    "substrate",
    "xposed",
    "magisk",
    "REJECT",         /* seccomp 相关 */
    "TracerPid",
    NULL
};

static int add_watch_string(const char *str)
{
    int i;
    int len = strlen(str);
    
    if (len <= 0 || len >= MEM_MON_MAX_STR_LEN)
        return -1;
    
    mem_mon_lock();
    for (i = 0; i < MEM_MON_MAX_WATCH_STRINGS; i++) {
        if (!g_mem_mon.watch_strings[i].active) {
            strncpy(g_mem_mon.watch_strings[i].value, str, MEM_MON_MAX_STR_LEN - 1);
            g_mem_mon.watch_strings[i].len = len;
            g_mem_mon.watch_strings[i].active = 1;
            g_mem_mon.watch_strings[i].hit_count = 0;
            g_mem_mon.watch_count++;
            mem_mon_unlock();
            return i;
        }
    }
    mem_mon_unlock();
    return -1;  /* 满了 */
}

static int remove_watch_string(const char *str)
{
    int i;
    mem_mon_lock();
    for (i = 0; i < MEM_MON_MAX_WATCH_STRINGS; i++) {
        if (g_mem_mon.watch_strings[i].active &&
            strcmp(g_mem_mon.watch_strings[i].value, str) == 0) {
            g_mem_mon.watch_strings[i].active = 0;
            g_mem_mon.watch_count--;
            mem_mon_unlock();
            return 0;
        }
    }
    mem_mon_unlock();
    return -1;
}

static void load_preset(const char **preset)
{
    int i;
    for (i = 0; preset[i]; i++) {
        add_watch_string(preset[i]);
    }
}

/* 
 * 处理 CTL 命令
 * 从你的 svc_monitor.c 的 ctl_handler 中调用
 */
int mem_mon_handle_ctl(const char *cmd, char *output, int output_size)
{
    if (strncmp(cmd, "mem_mon_enable", 14) == 0) {
        const char *pid_str = cmd + 14;
        while (*pid_str == ' ') pid_str++;
        
        if (*pid_str) {
            /* kstrtoint 等 */
            long pid_val = 0;
            /* 简化: 手动解析 */
            while (*pid_str >= '0' && *pid_str <= '9') {
                pid_val = pid_val * 10 + (*pid_str - '0');
                pid_str++;
            }
            g_mem_mon.target_pid = (pid_t)pid_val;
        }
        
        g_mem_mon.enabled = 1;
        return snprintf(output, output_size,
            "mem_monitor: ENABLED (pid=%d, watching %d strings)\n",
            g_mem_mon.target_pid, g_mem_mon.watch_count);
    }
    
    if (strcmp(cmd, "mem_mon_disable") == 0) {
        g_mem_mon.enabled = 0;
        return snprintf(output, output_size, "mem_monitor: DISABLED\n");
    }
    
    if (strncmp(cmd, "mem_mon_watch ", 13) == 0) {
        const char *str = cmd + 13;
        while (*str == ' ') str++;
        int idx = add_watch_string(str);
        if (idx >= 0)
            return snprintf(output, output_size,
                "mem_monitor: watching '%s' (slot %d, total %d)\n",
                str, idx, g_mem_mon.watch_count);
        else
            return snprintf(output, output_size,
                "mem_monitor: failed to add '%s' (full?)\n", str);
    }
    
    if (strncmp(cmd, "mem_mon_unwatch ", 15) == 0) {
        const char *str = cmd + 15;
        while (*str == ' ') str++;
        remove_watch_string(str);
        return snprintf(output, output_size,
            "mem_monitor: unwatched '%s' (total %d)\n",
            str, g_mem_mon.watch_count);
    }
    
    if (strcmp(cmd, "mem_mon_unwatch_all") == 0) {
        int i;
        for (i = 0; i < MEM_MON_MAX_WATCH_STRINGS; i++)
            g_mem_mon.watch_strings[i].active = 0;
        g_mem_mon.watch_count = 0;
        return snprintf(output, output_size, "mem_monitor: all strings cleared\n");
    }
    
    if (strcmp(cmd, "mem_mon_preset_frida") == 0) {
        load_preset(PRESET_FRIDA);
        return snprintf(output, output_size,
            "mem_monitor: loaded Frida preset (%d strings)\n",
            g_mem_mon.watch_count);
    }
    
    if (strcmp(cmd, "mem_mon_preset_xjd") == 0) {
        load_preset(PRESET_XJD);
        return snprintf(output, output_size,
            "mem_monitor: loaded xjd preset (%d strings)\n",
            g_mem_mon.watch_count);
    }
    
    if (strncmp(cmd, "mem_mon_maps_filter", 18) == 0) {
        const char *arg = cmd + 18;
        while (*arg == ' ') arg++;
        if (strcmp(arg, "on") == 0 || strcmp(arg, "1") == 0) {
            g_maps_filter_enabled = 1;
            return snprintf(output, output_size,
                "mem_monitor: maps filter ENABLED\n");
        } else {
            g_maps_filter_enabled = 0;
            return snprintf(output, output_size,
                "mem_monitor: maps filter DISABLED\n");
        }
    }
    
    if (strcmp(cmd, "mem_mon_status") == 0) {
        int n = 0;
        n += snprintf(output + n, output_size - n,
            "=== Memory Monitor Status ===\n"
            "enabled: %d\n"
            "target_pid: %d\n"
            "maps_filter: %d\n"
            "watch_count: %d\n"
            "log_entries: %lu\n"
            "--- Stats ---\n"
            "maps_opens: %lu\n"
            "maps_reads: %lu\n"
            "string_hits: %lu\n"
            "suspicious: %lu\n"
            "--- Watch Strings ---\n",
            g_mem_mon.enabled,
            g_mem_mon.target_pid,
            g_maps_filter_enabled,
            g_mem_mon.watch_count,
            g_mem_mon.log_total,
            g_mem_mon.stat_maps_opens,
            g_mem_mon.stat_maps_reads,
            g_mem_mon.stat_string_hits,
            g_mem_mon.stat_suspicious);
        
        int i;
        for (i = 0; i < MEM_MON_MAX_WATCH_STRINGS && n < output_size - 64; i++) {
            if (g_mem_mon.watch_strings[i].active) {
                n += snprintf(output + n, output_size - n,
                    "  [%d] '%s' (hits: %lu)\n",
                    i, g_mem_mon.watch_strings[i].value,
                    g_mem_mon.watch_strings[i].hit_count);
            }
        }
        return n;
    }
    
    if (strcmp(cmd, "mem_mon_clear") == 0) {
        mem_mon_lock();
        g_mem_mon.log_head = 0;
        g_mem_mon.log_tail = 0;
        g_mem_mon.log_total = 0;
        mem_mon_unlock();
        return snprintf(output, output_size, "mem_monitor: log cleared\n");
    }
    
    if (strcmp(cmd, "mem_mon_dump") == 0) {
        /* 导出最近的日志条目 */
        int n = 0;
        unsigned long i;
        unsigned long start = g_mem_mon.log_head > 50 ? g_mem_mon.log_head - 50 : 0;
        
        n += snprintf(output + n, output_size - n,
            "=== Memory Monitor Log (last 50) ===\n");
        
        for (i = start; i < g_mem_mon.log_head && n < output_size - 256; i++) {
            struct mem_access_log *e = &g_mem_mon.log_buf[i % MEM_MON_MAX_LOG_ENTRIES];
            
            const char *type_str = "?";
            switch (e->event_type) {
            case MEM_EVT_MAPS_OPEN:  type_str = "MAPS_OPEN"; break;
            case MEM_EVT_MAPS_READ:  type_str = "MAPS_READ"; break;
            case MEM_EVT_READ_MATCH: type_str = "READ_MATCH"; break;
            case MEM_EVT_MEM_SCAN:   type_str = "MEM_SCAN"; break;
            case MEM_EVT_PROC_OPEN:  type_str = "PROC_OPEN"; break;
            case MEM_EVT_SUSPICIOUS: type_str = "SUSPICIOUS"; break;
            }
            
            n += snprintf(output + n, output_size - n,
                "[%lu] %s pid=%d tid=%d comm=%s pc=0x%lx lr=0x%lx nr=%d",
                e->timestamp_ns / 1000000,  /* ms */
                type_str, e->pid, e->tid, e->comm,
                e->pc, e->lr, e->syscall_nr);
            
            if (e->event_type == MEM_EVT_MAPS_OPEN || e->event_type == MEM_EVT_PROC_OPEN) {
                n += snprintf(output + n, output_size - n,
                    " path=%s", e->data.open_event.pathname);
            }
            else if (e->event_type == MEM_EVT_READ_MATCH || e->event_type == MEM_EVT_MAPS_READ) {
                n += snprintf(output + n, output_size - n,
                    " fd=%d ret=%ld match=%d ctx='%.32s'",
                    e->data.read_event.fd,
                    (long)e->data.read_event.ret,
                    e->data.read_event.matched_str_idx,
                    e->data.read_event.matched_context);
            }
            
            n += snprintf(output + n, output_size - n, "\n");
        }
        return n;
    }
    
    return -1;  /* 未识别的命令 */
}

/* ═══════════════════════════════════════════════
 * 初始化 / 清理
 * ═══════════════════════════════════════════════ */

int mem_mon_init(void)
{
    memset(&g_mem_mon, 0, sizeof(g_mem_mon));
    
    g_mem_mon.log_buf = vmalloc(sizeof(struct mem_access_log) * MEM_MON_MAX_LOG_ENTRIES);
    if (!g_mem_mon.log_buf)
        return -1;
    
    memset(g_mem_mon.log_buf, 0, 
           sizeof(struct mem_access_log) * MEM_MON_MAX_LOG_ENTRIES);
    
    printk(KERN_INFO "mem_monitor: initialized (%d log slots, %d watch slots)\n",
           MEM_MON_MAX_LOG_ENTRIES, MEM_MON_MAX_WATCH_STRINGS);
    return 0;
}

void mem_mon_exit(void)
{
    g_mem_mon.enabled = 0;
    
    if (g_mem_mon.log_buf) {
        vfree(g_mem_mon.log_buf);
        g_mem_mon.log_buf = NULL;
    }
    
    printk(KERN_INFO "mem_monitor: cleaned up (total events: %lu, string hits: %lu)\n",
           g_mem_mon.log_total, g_mem_mon.stat_string_hits);
}
