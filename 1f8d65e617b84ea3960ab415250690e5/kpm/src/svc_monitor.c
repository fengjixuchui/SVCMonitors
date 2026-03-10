/* svc_monitor.c - KPM v9.0.0
 * ARM64 SVC system-call monitor for Pixel 6 / Android 12 / kernel 5.10
 * KernelPatch Module - CTL0 command interface
 *
 * ALL symbols verified against KPM SDK (bmax121/KernelPatch):
 *   - hook: inline_hook_syscalln / inline_unhook_syscalln / fp_hook_syscalln / fp_unhook_syscalln
 *   - args: syscall_argn (from <syscall.h>)
 *   - user: compat_strncpy_from_user / compat_copy_from_user / compat_copy_to_user
 *   - alloc: kp_malloc / kp_free (from <kpmalloc.h>)
 *   - sym: kallsyms_lookup_name (from <kallsyms.h>)
 *   - io: raw_syscall0-6 (from <syscall.h>)
 *   - misc: current_uid() (from <kputils.h>)
 *   - kern: printk/snprintf/strlen/strcmp/strncmp/memset/memcpy (from linux headers)
 *
 * New in v9:
 *   - Caller address -> SO name + offset resolution via /proc/<pid>/maps
 *   - File operation syscalls: full path resolution
 *   - clone/clone3: function pointer (child entry) recording
 *   - connect/bind: sockaddr parsing (IP + port)
 *   - execve: full argv[0..2] capture
 *   - mmap: prot/flags human-readable decode
 *   - kp_malloc/kp_free for dynamic buffers
 *   - Dual hook strategy: inline_hook first, fp_hook fallback
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kpmalloc.h>
#include <kputils.h>
#include <syscall.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("svc_monitor");
KPM_VERSION("9.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("SVC Monitor");
KPM_DESCRIPTION("ARM64 SVC syscall monitor with caller SO resolution and deep arg parsing");

/* ================================================================
 * ARM64 syscall numbers (kernel 5.10)
 * ================================================================ */
#define NR_io_setup 0
#define NR_io_submit 2
#define NR_io_cancel 3
#define NR_setxattr 5
#define NR_getxattr 8
#define NR_listxattr 11
#define NR_removexattr 14
#define NR_ioctl 29
#define NR_faccessat 48
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_read 63
#define NR_write 64
#define NR_readv 65
#define NR_writev 66
#define NR_pread64 67
#define NR_pwrite64 68
#define NR_sendfile 71
#define NR_pselect6 72
#define NR_ppoll 73
#define NR_readlinkat 78
#define NR_fstatat 79
#define NR_fstat 80
#define NR_fsync 82
#define NR_fdatasync 83
#define NR_ftruncate 46
#define NR_fallocate 47
#define NR_fchmod 52
#define NR_fchmodat 53
#define NR_fchown 55
#define NR_fchownat 54
#define NR_mkdirat 34
#define NR_mknodat 33
#define NR_unlinkat 35
#define NR_renameat 38
#define NR_renameat2 276
#define NR_linkat 37
#define NR_symlinkat 36
#define NR_lseek 62
#define NR_splice 76
#define NR_statfs 43
#define NR_fstatfs 44
#define NR_dup 23
#define NR_dup3 24
#define NR_fcntl 25
#define NR_inotify_init1 26
#define NR_inotify_add_watch 27
#define NR_inotify_rm_watch 28
#define NR_epoll_create1 20
#define NR_epoll_ctl 21
#define NR_epoll_pwait 22
#define NR_timerfd_create 85
#define NR_timerfd_settime 86
#define NR_eventfd2 19
#define NR_signalfd4 74
#define NR_socket 198
#define NR_socketpair 199
#define NR_bind 200
#define NR_listen 201
#define NR_accept4 242
#define NR_connect 203
#define NR_getsockname 204
#define NR_getpeername 205
#define NR_sendto 206
#define NR_recvfrom 207
#define NR_setsockopt 208
#define NR_getsockopt 209
#define NR_shutdown 210
#define NR_sendmsg 211
#define NR_recvmsg 212
#define NR_mmap 222
#define NR_mprotect 226
#define NR_munmap 215
#define NR_mremap 216
#define NR_madvise 233
#define NR_msync 227
#define NR_mlock 228
#define NR_munlock 229
#define NR_brk 214
#define NR_clone 220
#define NR_clone3 435
#define NR_execve 221
#define NR_exit 93
#define NR_exit_group 94
#define NR_wait4 260
#define NR_waitid 95
#define NR_kill 129
#define NR_tgkill 131
#define NR_tkill 130
#define NR_rt_sigaction 134
#define NR_rt_sigprocmask 135
#define NR_rt_sigreturn 139
#define NR_setuid 146
#define NR_setgid 144
#define NR_setresuid 147
#define NR_setresgid 149
#define NR_getuid 174
#define NR_geteuid 175
#define NR_getgid 176
#define NR_getegid 177
#define NR_gettid 178
#define NR_getpid 172
#define NR_getppid 173
#define NR_prctl 167
#define NR_ptrace 117
#define NR_mount 40
#define NR_umount2 39
#define NR_pivot_root 41
#define NR_chdir 49
#define NR_fchdir 50
#define NR_chroot 51
#define NR_futex 98
#define NR_set_robust_list 99
#define NR_capget 90
#define NR_capset 91
#define NR_personality 92
#define NR_seccomp 277
#define NR_bpf 280
#define NR_perf_event_open 241
#define NR_io_uring_setup 425
#define NR_io_uring_enter 426
#define NR_copy_file_range 285
#define NR_getrandom 278
#define NR_memfd_create 279
#define NR_userfaultfd 282
#define NR_pidfd_open 434
#define NR_pidfd_send_signal 424
#define NR_setns 268
#define NR_unshare 97

#define MAX_EVENTS      1024
#define MAX_DESC_LEN    512
#define MAX_PATH_LEN    256
#define MAX_CALLER_INFO 256
#define OUTBUF_SIZE     (256 * 1024)
#define OUTPUT_PATH     "/data/local/tmp/svc_output.json"
#define MAPS_PATH_FMT   "/proc/%d/maps"
#define TASK_COMM_LEN   16
#define BITMAP_LONGS    8
#define BITMAP_BITS     512

/* ================================================================
 * Syscall name lookup table
 * ================================================================ */
struct nr_entry { int nr; const char *name; };
static const struct nr_entry g_nr_table[] = {
    { 0, "io_setup" },
    { 2, "io_submit" },
    { 3, "io_cancel" },
    { 5, "setxattr" },
    { 8, "getxattr" },
    { 11, "listxattr" },
    { 14, "removexattr" },
    { 19, "eventfd2" },
    { 20, "epoll_create1" },
    { 21, "epoll_ctl" },
    { 22, "epoll_pwait" },
    { 23, "dup" },
    { 24, "dup3" },
    { 25, "fcntl" },
    { 26, "inotify_init1" },
    { 27, "inotify_add_watch" },
    { 28, "inotify_rm_watch" },
    { 29, "ioctl" },
    { 33, "mknodat" },
    { 34, "mkdirat" },
    { 35, "unlinkat" },
    { 36, "symlinkat" },
    { 37, "linkat" },
    { 38, "renameat" },
    { 39, "umount2" },
    { 40, "mount" },
    { 41, "pivot_root" },
    { 43, "statfs" },
    { 44, "fstatfs" },
    { 46, "ftruncate" },
    { 47, "fallocate" },
    { 48, "faccessat" },
    { 49, "chdir" },
    { 50, "fchdir" },
    { 51, "chroot" },
    { 52, "fchmod" },
    { 53, "fchmodat" },
    { 54, "fchownat" },
    { 55, "fchown" },
    { 56, "openat" },
    { 57, "close" },
    { 59, "pipe2" },
    { 62, "lseek" },
    { 63, "read" },
    { 64, "write" },
    { 65, "readv" },
    { 66, "writev" },
    { 67, "pread64" },
    { 68, "pwrite64" },
    { 71, "sendfile" },
    { 72, "pselect6" },
    { 73, "ppoll" },
    { 74, "signalfd4" },
    { 76, "splice" },
    { 78, "readlinkat" },
    { 79, "fstatat" },
    { 80, "fstat" },
    { 82, "fsync" },
    { 83, "fdatasync" },
    { 85, "timerfd_create" },
    { 86, "timerfd_settime" },
    { 90, "capget" },
    { 91, "capset" },
    { 92, "personality" },
    { 93, "exit" },
    { 94, "exit_group" },
    { 95, "waitid" },
    { 97, "unshare" },
    { 98, "futex" },
    { 99, "set_robust_list" },
    { 117, "ptrace" },
    { 129, "kill" },
    { 130, "tkill" },
    { 131, "tgkill" },
    { 134, "rt_sigaction" },
    { 135, "rt_sigprocmask" },
    { 139, "rt_sigreturn" },
    { 144, "setgid" },
    { 146, "setuid" },
    { 147, "setresuid" },
    { 149, "setresgid" },
    { 167, "prctl" },
    { 172, "getpid" },
    { 173, "getppid" },
    { 174, "getuid" },
    { 175, "geteuid" },
    { 176, "getgid" },
    { 177, "getegid" },
    { 178, "gettid" },
    { 198, "socket" },
    { 199, "socketpair" },
    { 200, "bind" },
    { 201, "listen" },
    { 203, "connect" },
    { 204, "getsockname" },
    { 205, "getpeername" },
    { 206, "sendto" },
    { 207, "recvfrom" },
    { 208, "setsockopt" },
    { 209, "getsockopt" },
    { 210, "shutdown" },
    { 211, "sendmsg" },
    { 212, "recvmsg" },
    { 214, "brk" },
    { 215, "munmap" },
    { 216, "mremap" },
    { 220, "clone" },
    { 221, "execve" },
    { 222, "mmap" },
    { 226, "mprotect" },
    { 227, "msync" },
    { 228, "mlock" },
    { 229, "munlock" },
    { 233, "madvise" },
    { 241, "perf_event_open" },
    { 242, "accept4" },
    { 260, "wait4" },
    { 268, "setns" },
    { 276, "renameat2" },
    { 277, "seccomp" },
    { 278, "getrandom" },
    { 279, "memfd_create" },
    { 280, "bpf" },
    { 282, "userfaultfd" },
    { 285, "copy_file_range" },
    { 424, "pidfd_send_signal" },
    { 425, "io_uring_setup" },
    { 426, "io_uring_enter" },
    { 434, "pidfd_open" },
    { 435, "clone3" },
    { -1, 0 }
};

static const char *nr_to_name(int nr) {
    int i;
    for (i = 0; g_nr_table[i].nr >= 0; i++)
        if (g_nr_table[i].nr == nr) return g_nr_table[i].name;
    return "unknown";
}

/* ================================================================
 * Event data structure
 * ================================================================ */
struct svc_event {
    unsigned long seq;
    int nr;
    int pid;
    int uid;
    char comm[TASK_COMM_LEN];
    unsigned long a0, a1, a2, a3, a4, a5;
    char desc[MAX_DESC_LEN];
    char caller_info[MAX_CALLER_INFO];  /* SO+offset or [anon:addr] */
    unsigned long caller_addr;
    unsigned long pc;
    char fd_path[MAX_PATH_LEN];
    unsigned long clone_fn;
};

/* ================================================================
 * Global state - all static allocation
 * ================================================================ */
static struct svc_event *g_events;  /* kp_malloc ring buffer */
static char *g_outbuf;             /* kp_malloc output buffer */
static volatile int g_head;
static volatile int g_tail;
static volatile int g_count;
static volatile unsigned long g_total;
static volatile unsigned long g_seq;
static volatile int g_enabled;
static int g_uid_filter;
static int g_tier2_enabled;
static int g_tier1_hooked;
static int g_tier2_hooked;

/* Bitmap NR filter */
static unsigned long g_nr_bitmap[BITMAP_LONGS];

/* ================================================================
 * Bitmap operations
 * ================================================================ */
static void bitmap_set(int nr) {
    if (nr < 0 || nr >= BITMAP_BITS) return;
    g_nr_bitmap[nr / (sizeof(unsigned long) * 8)] |= (1UL << (nr % (sizeof(unsigned long) * 8)));
}
static void bitmap_clear(int nr) {
    if (nr < 0 || nr >= BITMAP_BITS) return;
    g_nr_bitmap[nr / (sizeof(unsigned long) * 8)] &= ~(1UL << (nr % (sizeof(unsigned long) * 8)));
}
static int bitmap_test(int nr) {
    if (nr < 0 || nr >= BITMAP_BITS) return 0;
    return (g_nr_bitmap[nr / (sizeof(unsigned long) * 8)] >> (nr % (sizeof(unsigned long) * 8))) & 1;
}
static void bitmap_set_all(void) { memset(g_nr_bitmap, 0xff, sizeof(g_nr_bitmap)); }
static void bitmap_clear_all(void) { memset(g_nr_bitmap, 0, sizeof(g_nr_bitmap)); }
static int bitmap_any_set(void) {
    int i; for (i = 0; i < BITMAP_LONGS; i++) if (g_nr_bitmap[i]) return 1; return 0;
}
static int bitmap_list(char *buf, int buflen) {
    int off = 0, first = 1, i;
    for (i = 0; i < BITMAP_BITS && off < buflen - 8; i++) {
        if (bitmap_test(i)) {
            off += snprintf(buf + off, buflen - off, "%s%d", first ? "" : ",", i);
            first = 0;
        }
    }
    if (off == 0) { buf[0] = '\0'; }
    return off;
}

/* ================================================================
 * Safe user-space access helpers (KPM API)
 * ================================================================ */
static long safe_strncpy_user(char *dst, unsigned long user_addr, int maxlen) {
    long ret;
    if (!user_addr || user_addr < 0x1000UL) { dst[0] = '\0'; return -1; }
    ret = compat_strncpy_from_user(dst, (const char __user *)user_addr, maxlen - 1);
    if (ret < 0) { dst[0] = '\0'; return ret; }
    dst[ret < maxlen - 1 ? ret : maxlen - 1] = '\0';
    return ret;
}

static unsigned long safe_read_ulong(unsigned long user_addr) {
    unsigned long val = 0;
    if (!user_addr || user_addr < 0x1000UL) return 0;
    if (compat_copy_from_user(&val, (void __user *)user_addr, sizeof(val)) != 0) return 0;
    return val;
}

/* ================================================================
 * Caller address -> SO + offset resolution
 *
 * Reads /proc/<pid>/maps via raw_syscall to find which
 * shared library or memory region contains the caller address.
 * Output format: "libfoo.so+0x1234" or "[anon:0xdead]" or "[vdso]"
 * ================================================================ */
static void resolve_caller(int pid, unsigned long addr, char *out, int outlen) {
    char maps_path[64];
    char *buf;
    long fd, nread;
    char *p, *line_start, *line_end;
    unsigned long vm_start, vm_end, offset;
    int found = 0;

    if (!addr || addr < 0x1000UL) {
        snprintf(out, outlen, "[kernel]");
        return;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    /* Allocate read buffer via kp_malloc */
    buf = (char *)kp_malloc(32768);
    if (!buf) {
        snprintf(out, outlen, "0x%lx", addr);
        return;
    }

    fd = raw_syscall3(__NR_openat, -100, (unsigned long)maps_path, 0 /* O_RDONLY */);
    if (fd < 0) {
        snprintf(out, outlen, "0x%lx", addr);
        kp_free(buf);
        return;
    }

    nread = raw_syscall3(__NR_read, fd, (unsigned long)buf, 32767);
    raw_syscall1(__NR_close, fd);

    if (nread <= 0) {
        snprintf(out, outlen, "0x%lx", addr);
        kp_free(buf);
        return;
    }
    buf[nread] = '\0';

    /* Parse maps lines: START-END PERMS OFFSET DEV INODE PATHNAME */
    line_start = buf;
    while (line_start < buf + nread && !found) {
        line_end = line_start;
        while (*line_end && *line_end != '\n') line_end++;

        /* Parse hex start address */
        vm_start = 0; vm_end = 0; offset = 0;
        p = line_start;
        while (p < line_end && *p != '-') {
            vm_start = (vm_start << 4);
            if (*p >= '0' && *p <= '9') vm_start |= (*p - '0');
            else if (*p >= 'a' && *p <= 'f') vm_start |= (*p - 'a' + 10);
            p++;
        }
        if (*p == '-') p++;
        while (p < line_end && *p != ' ') {
            vm_end = (vm_end << 4);
            if (*p >= '0' && *p <= '9') vm_end |= (*p - '0');
            else if (*p >= 'a' && *p <= 'f') vm_end |= (*p - 'a' + 10);
            p++;
        }

        if (addr >= vm_start && addr < vm_end) {
            /* Found! Skip perms field */
            while (p < line_end && *p == ' ') p++;  /* skip space */
            while (p < line_end && *p != ' ') p++;  /* skip perms */
            while (p < line_end && *p == ' ') p++;  /* skip space */
            /* Parse offset */
            while (p < line_end && *p != ' ') {
                offset = (offset << 4);
                if (*p >= '0' && *p <= '9') offset |= (*p - '0');
                else if (*p >= 'a' && *p <= 'f') offset |= (*p - 'a' + 10);
                p++;
            }
            /* Skip dev and inode fields */
            while (p < line_end && *p == ' ') p++;
            while (p < line_end && *p != ' ') p++;  /* dev */
            while (p < line_end && *p == ' ') p++;
            while (p < line_end && *p != ' ' && *p != '\n') p++;  /* inode */
            while (p < line_end && *p == ' ') p++;

            /* Now p points to pathname (or end of line for anon) */
            if (p < line_end && *p != '\0' && *p != '\n') {
                /* Has pathname - extract basename */
                char *name_start = p;
                char *slash = p;
                while (p < line_end && *p != '\n' && *p != '\0') {
                    if (*p == '/') slash = p + 1;
                    p++;
                }
                /* Calculate file offset = (addr - vm_start) + file_offset */
                {
                    unsigned long file_off = (addr - vm_start) + offset;
                    int nlen = (int)(p - slash);
                    if (nlen > 80) nlen = 80;
                    snprintf(out, outlen, "%.*s+0x%lx", nlen, slash, file_off);
                }
            } else {
                /* Anonymous mapping */
                snprintf(out, outlen, "[anon:%lx--%lx]+0x%lx",
                         vm_start, vm_end, addr - vm_start);
            }
            found = 1;
        }
        line_start = line_end + 1;
    }

    if (!found)
        snprintf(out, outlen, "0x%lx", addr);

    kp_free(buf);
}

/* ================================================================
 * fd -> file path resolution via /proc/self/fd/<N> readlink
 * ================================================================ */
static void resolve_fd_path(int pid, int fd, char *out, int outlen) {
    char link_path[64];
    long ret;
    if (fd < 0) { out[0] = '\0'; return; }
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", pid, fd);
    ret = raw_syscall4(__NR_readlinkat, -100, (unsigned long)link_path, (unsigned long)out, outlen - 1);
    if (ret > 0) out[ret] = '\0';
    else out[0] = '\0';
}

/* ================================================================
 * JSON string escape
 * ================================================================ */
static void json_escape(char *dst, int dstlen, const char *src) {
    int si = 0, di = 0;
    if (!src) { dst[0] = '\0'; return; }
    while (src[si] && di < dstlen - 6) {
        unsigned char ch = (unsigned char)src[si];
        if (ch == '"') { dst[di++] = '\\'; dst[di++] = '"'; }
        else if (ch == '\\') { dst[di++] = '\\'; dst[di++] = '\\'; }
        else if (ch == '\n') { dst[di++] = '\\'; dst[di++] = 'n'; }
        else if (ch == '\r') { dst[di++] = '\\'; dst[di++] = 'r'; }
        else if (ch == '\t') { dst[di++] = '\\'; dst[di++] = 't'; }
        else if (ch >= 0x20 && ch < 0x7f) { dst[di++] = ch; }
        else {
            /* hex escape for non-printable */
            dst[di++] = '\\'; dst[di++] = 'x';
            dst[di++] = "0123456789abcdef"[(ch >> 4) & 0xf];
            dst[di++] = "0123456789abcdef"[ch & 0xf];
        }
        si++;
    }
    dst[di] = '\0';
}

/* ================================================================
 * Process info helpers (KPM-safe)
 * ================================================================ */
static int get_current_pid(void) { return (int)raw_syscall0(__NR_gettid); }
static int get_current_tgid(void) { return (int)raw_syscall0(__NR_getpid); }

static void get_current_comm(char *buf, int len) {
    long ret = raw_syscall2(157 /* __NR_prctl */, 16 /* PR_GET_NAME */, (unsigned long)buf);
    if (ret != 0) {
        memset(buf, 0, len);
        memcpy(buf, "?", 2);
    }
}

/* ================================================================
 * Get caller return address from ARM64 stack frame
 * On ARM64, x30 (LR) holds the return address.
 * We use __builtin_return_address as a fallback.
 * ================================================================ */
static unsigned long get_caller_lr(void) {
    return (unsigned long)__builtin_return_address(0);
}

/* ================================================================
 * File I/O via raw_syscall (KPM-safe, no filp_open)
 * ================================================================ */
static int write_output_file(const char *path, const char *buf, int len) {
    long fd = raw_syscall3(__NR_openat, -100, (unsigned long)path,
                           0x241 /* O_WRONLY|O_CREAT|O_TRUNC */);
    if (fd < 0) return -1;
    raw_syscall3(__NR_write, fd, (unsigned long)buf, len);
    raw_syscall1(__NR_close, fd);
    return 0;
}

/* ================================================================
 * Deep argument parsing for major syscalls
 *
 * Key enhancements in v9:
 *   - openat/unlinkat/etc: full path extraction
 *   - clone: child function pointer resolution
 *   - connect/bind: sockaddr IP:port decode
 *   - execve: argv[0..2] capture
 *   - mmap: prot/flags decode
 *   - read/write: fd path auto-resolve
 * ================================================================ */
static void parse_mmap_prot(unsigned long prot, char *buf, int len) {
    int off = 0;
    if (prot == 0) { memcpy(buf, "NONE", 5); return; }
    if (prot & 1) off += snprintf(buf + off, len - off, "R");
    if (prot & 2) off += snprintf(buf + off, len - off, "W");
    if (prot & 4) off += snprintf(buf + off, len - off, "X");
    buf[off] = '\0';
}

static void parse_mmap_flags(unsigned long flags, char *buf, int len) {
    int off = 0;
    if (flags & 0x01) off += snprintf(buf + off, len - off, "SHARED|");
    if (flags & 0x02) off += snprintf(buf + off, len - off, "PRIVATE|");
    if (flags & 0x10) off += snprintf(buf + off, len - off, "FIXED|");
    if (flags & 0x20) off += snprintf(buf + off, len - off, "ANON|");
    if (off > 0) buf[off - 1] = '\0';
    else buf[0] = '\0';
}

static void parse_sockaddr(unsigned long sa_ptr, char *out, int outlen) {
    unsigned char sabuf[128];
    unsigned short family;
    if (!sa_ptr || compat_copy_from_user(sabuf, (void __user *)sa_ptr, 128) != 0) {
        snprintf(out, outlen, "?"); return;
    }
    family = sabuf[0] | (sabuf[1] << 8);
    if (family == 2) {  /* AF_INET */
        unsigned short port = (sabuf[2] << 8) | sabuf[3];
        snprintf(out, outlen, "%d.%d.%d.%d:%d",
                 sabuf[4], sabuf[5], sabuf[6], sabuf[7], port);
    } else if (family == 10) {  /* AF_INET6 */
        unsigned short port = (sabuf[2] << 8) | sabuf[3];
        snprintf(out, outlen, "[::...ipv6]:%d", port);
    } else if (family == 1) {  /* AF_UNIX */
        snprintf(out, outlen, "unix:%s", (char *)&sabuf[2]);
    } else {
        snprintf(out, outlen, "family=%d", family);
    }
}

static void deep_parse_args(struct svc_event *ev) {
    char tmp[MAX_PATH_LEN];
    char tmp2[MAX_PATH_LEN];
    int off = 0;
    int pid = ev->pid;

    switch (ev->nr) {
    case 56: /* openat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" flags=0x%lx mode=0%lo",
                       (int)ev->a0, tmp, ev->a2, ev->a3);
        break;
    case 35: /* unlinkat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" flags=0x%lx",
                       (int)ev->a0, tmp, ev->a2);
        break;
    case 34: /* mkdirat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" mode=0%lo",
                       (int)ev->a0, tmp, ev->a2);
        break;
    case 48: /* faccessat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" mode=%d",
                       (int)ev->a0, tmp, (int)ev->a2);
        break;
    case 53: /* fchmodat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" mode=0%lo",
                       (int)ev->a0, tmp, ev->a2);
        break;
    case 54: /* fchownat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" uid=%d gid=%d",
                       (int)ev->a0, tmp, (int)ev->a2, (int)ev->a3);
        break;
    case 78: /* readlinkat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\" bufsiz=%lu",
                       (int)ev->a0, tmp, ev->a2);
        break;
    case 79: /* fstatat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dfd=%d path=\"%s\"",
                       (int)ev->a0, tmp);
        break;
    case NR_renameat: case NR_renameat2: /* rename */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        safe_strncpy_user(tmp2, ev->a3, sizeof(tmp2));
        off = snprintf(ev->desc, MAX_DESC_LEN, "olddfd=%d old=\"%s\" newdfd=%d new=\"%s\"",
                       (int)ev->a0, tmp, (int)ev->a2, tmp2);
        break;
    case NR_symlinkat: /* symlinkat */
        safe_strncpy_user(tmp, ev->a0, sizeof(tmp));
        safe_strncpy_user(tmp2, ev->a2, sizeof(tmp2));
        off = snprintf(ev->desc, MAX_DESC_LEN, "target=\"%s\" newdfd=%d linkpath=\"%s\"",
                       tmp, (int)ev->a1, tmp2);
        break;
    case NR_linkat: /* linkat */
        safe_strncpy_user(tmp, ev->a1, sizeof(tmp));
        safe_strncpy_user(tmp2, ev->a3, sizeof(tmp2));
        off = snprintf(ev->desc, MAX_DESC_LEN, "olddfd=%d old=\"%s\" newdfd=%d new=\"%s\" flags=0x%lx",
                       (int)ev->a0, tmp, (int)ev->a2, tmp2, ev->a4);
        break;
    case NR_read: /* read - resolve fd path */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] count=%lu",
                       (int)ev->a0, ev->fd_path, ev->a2);
        break;
    case NR_write: /* write - resolve fd path */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] count=%lu",
                       (int)ev->a0, ev->fd_path, ev->a2);
        break;
    case 65: /* readv */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] iovcnt=%lu", (int)ev->a0, ev->fd_path, ev->a2);
        break;
    case 66: /* writev */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] iovcnt=%lu", (int)ev->a0, ev->fd_path, ev->a2);
        break;
    case 67: /* pread64 */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] count=%lu offset=%ld", (int)ev->a0, ev->fd_path, ev->a2, (long)ev->a3);
        break;
    case 68: /* pwrite64 */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] count=%lu offset=%ld", (int)ev->a0, ev->fd_path, ev->a2, (long)ev->a3);
        break;
    case 82: /* fsync */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s]", (int)ev->a0, ev->fd_path);
        break;
    case 83: /* fdatasync */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s]", (int)ev->a0, ev->fd_path);
        break;
    case 57: /* close */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s]", (int)ev->a0, ev->fd_path);
        break;
    case 62: /* lseek */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] offset=%ld whence=%d", (int)ev->a0, ev->fd_path, (long)ev->a1, (int)ev->a2);
        break;
    case 80: /* fstat */
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s]", (int)ev->a0, ev->fd_path);
        break;
    case NR_execve: /* execve - capture filename + argv[0..2] */ {
        char arg0[128], arg1[128], arg2[128];
        unsigned long argv_ptr;
        safe_strncpy_user(tmp, ev->a0, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "filename=\"%s\"", tmp);
        argv_ptr = ev->a1;
        if (argv_ptr) {
            unsigned long p0 = safe_read_ulong(argv_ptr);
            unsigned long p1 = safe_read_ulong(argv_ptr + 8);
            unsigned long p2 = safe_read_ulong(argv_ptr + 16);
            if (p0) { safe_strncpy_user(arg0, p0, sizeof(arg0));
                off += snprintf(ev->desc + off, MAX_DESC_LEN - off, " argv[0]=\"%s\"", arg0); }
            if (p1) { safe_strncpy_user(arg1, p1, sizeof(arg1));
                off += snprintf(ev->desc + off, MAX_DESC_LEN - off, " argv[1]=\"%s\"", arg1); }
            if (p2) { safe_strncpy_user(arg2, p2, sizeof(arg2));
                off += snprintf(ev->desc + off, MAX_DESC_LEN - off, " argv[2]=\"%s\"", arg2); }
        }
        break;
    }
    case NR_clone: /* clone - capture child function pointer */
        off = snprintf(ev->desc, MAX_DESC_LEN, "flags=0x%lx stack=0x%lx", ev->a0, ev->a1);
        /* a5 often contains the function pointer for the child */
        ev->clone_fn = ev->a5;
        if (ev->clone_fn > 0x1000)
            resolve_caller(pid, ev->clone_fn, tmp, sizeof(tmp));
        else tmp[0] = '\0';
        if (tmp[0])
            off += snprintf(ev->desc + off, MAX_DESC_LEN - off, " child_fn=%s", tmp);
        break;
    case NR_clone3: /* clone3 - args struct */ {
        unsigned long fn = 0;
        off = snprintf(ev->desc, MAX_DESC_LEN, "args=0x%lx size=%lu", ev->a0, ev->a1);
        /* clone_args.entry_func is at offset 48 on ARM64 5.10 */
        if (ev->a0) fn = safe_read_ulong(ev->a0 + 48);
        ev->clone_fn = fn;
        if (fn > 0x1000) {
            resolve_caller(pid, fn, tmp, sizeof(tmp));
            off += snprintf(ev->desc + off, MAX_DESC_LEN - off, " child_fn=%s", tmp);
        }
        break;
    }
    case NR_socket: /* socket */
        off = snprintf(ev->desc, MAX_DESC_LEN, "domain=%d type=%d protocol=%d",
                       (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case NR_connect: /* connect - decode sockaddr */ {
        char addr_str[128];
        parse_sockaddr(ev->a1, addr_str, sizeof(addr_str));
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d addr=%s addrlen=%d",
                       (int)ev->a0, addr_str, (int)ev->a2);
        break;
    }
    case NR_bind: /* bind - decode sockaddr */ {
        char addr_str[128];
        parse_sockaddr(ev->a1, addr_str, sizeof(addr_str));
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d addr=%s addrlen=%d",
                       (int)ev->a0, addr_str, (int)ev->a2);
        break;
    }
    case NR_listen:
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d backlog=%d", (int)ev->a0, (int)ev->a1);
        break;
    case NR_accept4:
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d flags=0x%lx", (int)ev->a0, ev->a3);
        break;
    case NR_sendto:
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d len=%lu flags=0x%lx",
                       (int)ev->a0, ev->a2, ev->a3);
        if (ev->a4) {
            char addr_str[128];
            parse_sockaddr(ev->a4, addr_str, sizeof(addr_str));
            off += snprintf(ev->desc + off, MAX_DESC_LEN - off, " dest=%s", addr_str);
        }
        break;
    case NR_recvfrom:
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d len=%lu flags=0x%lx",
                       (int)ev->a0, ev->a2, ev->a3);
        break;
    case NR_mmap: /* mmap - decode prot and flags */ {
        char prot_str[16], flags_str[64];
        parse_mmap_prot(ev->a2, prot_str, sizeof(prot_str));
        parse_mmap_flags(ev->a3, flags_str, sizeof(flags_str));
        off = snprintf(ev->desc, MAX_DESC_LEN, "addr=0x%lx len=%lu prot=%s flags=%s fd=%d offset=%ld",
                       ev->a0, ev->a1, prot_str, flags_str, (int)ev->a4, (long)ev->a5);
        if ((int)ev->a4 >= 0)
            resolve_fd_path(pid, (int)ev->a4, ev->fd_path, MAX_PATH_LEN);
        break;
    }
    case NR_mprotect:
        { char prot_str[16]; parse_mmap_prot(ev->a2, prot_str, sizeof(prot_str));
        off = snprintf(ev->desc, MAX_DESC_LEN, "addr=0x%lx len=%lu prot=%s",
                       ev->a0, ev->a1, prot_str); break; }
    case NR_munmap:
        off = snprintf(ev->desc, MAX_DESC_LEN, "addr=0x%lx len=%lu", ev->a0, ev->a1);
        break;
    case NR_kill:
        off = snprintf(ev->desc, MAX_DESC_LEN, "pid=%d sig=%d", (int)ev->a0, (int)ev->a1);
        break;
    case NR_tgkill:
        off = snprintf(ev->desc, MAX_DESC_LEN, "tgid=%d tid=%d sig=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case NR_tkill:
        off = snprintf(ev->desc, MAX_DESC_LEN, "tid=%d sig=%d", (int)ev->a0, (int)ev->a1);
        break;
    case NR_exit: case NR_exit_group:
        off = snprintf(ev->desc, MAX_DESC_LEN, "status=%d", (int)ev->a0);
        break;
    case NR_wait4:
        off = snprintf(ev->desc, MAX_DESC_LEN, "pid=%d options=0x%lx", (int)ev->a0, ev->a2);
        break;
    case NR_prctl:
        off = snprintf(ev->desc, MAX_DESC_LEN, "option=%d arg2=0x%lx arg3=0x%lx",
                       (int)ev->a0, ev->a1, ev->a2);
        break;
    case NR_ioctl:
        resolve_fd_path(pid, (int)ev->a0, ev->fd_path, MAX_PATH_LEN);
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d[%s] cmd=0x%lx arg=0x%lx",
                       (int)ev->a0, ev->fd_path, ev->a1, ev->a2);
        break;
    case NR_mount: /* mount */
        safe_strncpy_user(tmp, ev->a0, sizeof(tmp));
        safe_strncpy_user(tmp2, ev->a1, sizeof(tmp2));
        off = snprintf(ev->desc, MAX_DESC_LEN, "dev=\"%s\" target=\"%s\" flags=0x%lx",
                       tmp, tmp2, ev->a3);
        break;
    case NR_umount2:
        safe_strncpy_user(tmp, ev->a0, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "target=\"%s\" flags=0x%lx", tmp, ev->a1);
        break;
    case NR_fcntl:
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd=%d cmd=%d arg=0x%lx", (int)ev->a0, (int)ev->a1, ev->a2);
        break;
    case NR_dup:
        off = snprintf(ev->desc, MAX_DESC_LEN, "oldfd=%d", (int)ev->a0);
        break;
    case NR_dup3:
        off = snprintf(ev->desc, MAX_DESC_LEN, "oldfd=%d newfd=%d flags=0x%lx", (int)ev->a0, (int)ev->a1, ev->a2);
        break;
    case NR_splice:
        off = snprintf(ev->desc, MAX_DESC_LEN, "fd_in=%d fd_out=%d len=%lu flags=0x%lx",
                       (int)ev->a0, (int)ev->a2, ev->a4, ev->a5);
        break;
    case NR_seccomp:
        off = snprintf(ev->desc, MAX_DESC_LEN, "op=%d flags=0x%lx", (int)ev->a0, ev->a1);
        break;
    case NR_bpf:
        off = snprintf(ev->desc, MAX_DESC_LEN, "cmd=%d attr=0x%lx size=%u", (int)ev->a0, ev->a1, (unsigned)ev->a2);
        break;
    case NR_ptrace:
        off = snprintf(ev->desc, MAX_DESC_LEN, "request=%d pid=%d addr=0x%lx data=0x%lx",
                       (int)ev->a0, (int)ev->a1, ev->a2, ev->a3);
        break;
    case NR_setuid:
        off = snprintf(ev->desc, MAX_DESC_LEN, "uid=%d", (int)ev->a0);
        break;
    case NR_setresuid:
        off = snprintf(ev->desc, MAX_DESC_LEN, "ruid=%d euid=%d suid=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case NR_epoll_ctl:
        off = snprintf(ev->desc, MAX_DESC_LEN, "epfd=%d op=%d fd=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case NR_futex:
        off = snprintf(ev->desc, MAX_DESC_LEN, "uaddr=0x%lx op=%d val=%d", ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case NR_memfd_create:
        safe_strncpy_user(tmp, ev->a0, sizeof(tmp));
        off = snprintf(ev->desc, MAX_DESC_LEN, "name=\"%s\" flags=0x%lx", tmp, ev->a1);
        break;
    case NR_getrandom:
        off = snprintf(ev->desc, MAX_DESC_LEN, "len=%lu flags=0x%lx", ev->a1, ev->a2);
        break;
    default:
        off = snprintf(ev->desc, MAX_DESC_LEN, "a0=0x%lx a1=0x%lx a2=0x%lx",
                       ev->a0, ev->a1, ev->a2);
        break;
    }
    (void)off;
}

/* ================================================================
 * Generic before-syscall hook callback
 * Called for all hooked syscalls via inline_hook/fp_hook
 * ================================================================ */
static void before_generic(hook_fargs6_t *args, void *udata) {
    int nr = (int)(unsigned long)udata;
    int uid, pid;
    struct svc_event *ev;
    int idx;

    if (!g_enabled) return;
    if (!bitmap_test(nr)) return;

    uid = (int)current_uid();
    if (g_uid_filter > 0 && uid != g_uid_filter) return;

    pid = get_current_pid();

    /* Ring buffer insert */
    idx = g_head;
    g_head = (g_head + 1) % MAX_EVENTS;
    if (g_count >= MAX_EVENTS)
        g_tail = (g_tail + 1) % MAX_EVENTS;
    else
        g_count++;
    g_total++;

    ev = &g_events[idx];
    memset(ev, 0, sizeof(*ev));
    ev->seq = ++g_seq;
    ev->nr = nr;
    ev->pid = pid;
    ev->uid = uid;
    get_current_comm(ev->comm, TASK_COMM_LEN);

    /* Capture raw args via syscall_argn */
    ev->a0 = syscall_argn(args, 0);
    ev->a1 = syscall_argn(args, 1);
    ev->a2 = syscall_argn(args, 2);
    ev->a3 = syscall_argn(args, 3);
    ev->a4 = syscall_argn(args, 4);
    ev->a5 = syscall_argn(args, 5);

    /* Caller address (LR) */
    ev->caller_addr = get_caller_lr();
    ev->pc = ev->caller_addr;

    /* Resolve caller to SO+offset */
    resolve_caller(pid, ev->caller_addr, ev->caller_info, MAX_CALLER_INFO);

    /* Deep argument parsing */
    deep_parse_args(ev);
}

/* ================================================================
 * Hook table and install/uninstall
 * Dual strategy: try inline_hook first, fallback to fp_hook
 * ================================================================ */
#define HOOK_INLINE 1
#define HOOK_FP     2

struct hook_entry {
    int nr;
    int narg;
    int installed;
    int method;  /* HOOK_INLINE or HOOK_FP */
};

#define TIER1_COUNT 46
#define TIER2_COUNT 25
#define TOTAL_HOOKS (TIER1_COUNT + TIER2_COUNT)

static struct hook_entry g_hooks[TOTAL_HOOKS];

static void init_hook_table(void) {
    int i = 0;
    g_hooks[i].nr = 56; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 57; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 63; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 64; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 65; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 66; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 67; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 68; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 35; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 34; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 48; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 78; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 79; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 80; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 82; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 83; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 62; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 76; g_hooks[i].narg = 6; i++;
    g_hooks[i].nr = 23; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 24; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 25; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 29; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 53; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 54; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 38; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 276; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 36; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 37; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 198; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 200; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 201; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 203; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 206; g_hooks[i].narg = 6; i++;
    g_hooks[i].nr = 207; g_hooks[i].narg = 6; i++;
    g_hooks[i].nr = 211; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 212; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 208; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 209; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 210; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 220; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 221; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 129; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 131; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 93; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 94; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 222; g_hooks[i].narg = 6; i++;
    g_hooks[i].nr = 435; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 242; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 226; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 215; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 216; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 233; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 227; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 228; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 229; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 214; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 40; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 39; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 117; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 167; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 260; g_hooks[i].narg = 4; i++;
    g_hooks[i].nr = 95; g_hooks[i].narg = 5; i++;
    g_hooks[i].nr = 130; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 277; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 280; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 146; g_hooks[i].narg = 1; i++;
    g_hooks[i].nr = 147; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 279; g_hooks[i].narg = 2; i++;
    g_hooks[i].nr = 278; g_hooks[i].narg = 3; i++;
    g_hooks[i].nr = 98; g_hooks[i].narg = 6; i++;
    g_hooks[i].nr = 21; g_hooks[i].narg = 4; i++;
}

static int install_single_hook(struct hook_entry *h) {
    hook_err_t err;
    if (h->installed) return 0;
    /* Try inline hook first */
    err = inline_hook_syscalln(h->nr, h->narg,
                               (void *)before_generic, (void *)0,
                               (void *)(unsigned long)h->nr);
    if (err == HOOK_NO_ERR) {
        h->installed = 1;
        h->method = HOOK_INLINE;
        return 0;
    }
    /* Fallback to fp hook */
    err = fp_hook_syscalln(h->nr, h->narg,
                           (void *)before_generic, (void *)0,
                           (void *)(unsigned long)h->nr);
    if (err == HOOK_NO_ERR) {
        h->installed = 1;
        h->method = HOOK_FP;
        return 0;
    }
    pr_warn("svc_monitor: failed to hook NR %d (err=%d)\n", h->nr, err);
    return -1;
}

static void uninstall_single_hook(struct hook_entry *h) {
    if (!h->installed) return;
    if (h->method == HOOK_INLINE)
        inline_unhook_syscalln(h->nr, (void *)before_generic, (void *)0);
    else
        fp_unhook_syscalln(h->nr, (void *)before_generic, (void *)0);
    h->installed = 0;
}

static void install_tier1(void) {
    int i;
    if (g_tier1_hooked) return;
    for (i = 0; i < TIER1_COUNT; i++)
        install_single_hook(&g_hooks[i]);
    g_tier1_hooked = 1;
    pr_info("svc_monitor: tier1 hooks installed (%d)\n", TIER1_COUNT);
}
static void remove_tier1(void) {
    int i;
    if (!g_tier1_hooked) return;
    for (i = 0; i < TIER1_COUNT; i++)
        uninstall_single_hook(&g_hooks[i]);
    g_tier1_hooked = 0;
    pr_info("svc_monitor: tier1 hooks removed\n");
}
static void install_tier2(void) {
    int i;
    if (g_tier2_hooked) return;
    for (i = TIER1_COUNT; i < TOTAL_HOOKS; i++)
        install_single_hook(&g_hooks[i]);
    g_tier2_hooked = 1;
    g_tier2_enabled = 1;
    pr_info("svc_monitor: tier2 hooks installed (%d)\n", TIER2_COUNT);
}
static void remove_tier2(void) {
    int i;
    if (!g_tier2_hooked) return;
    for (i = TIER1_COUNT; i < TOTAL_HOOKS; i++)
        uninstall_single_hook(&g_hooks[i]);
    g_tier2_hooked = 0;
    g_tier2_enabled = 0;
    pr_info("svc_monitor: tier2 hooks removed\n");
}

/* ================================================================
 * Presets
 * ================================================================ */
static const int preset_file_io[] = { 56, 57, 63, 64, 65, 66, 67, 68, 62, 76, 82, 83 };
static const int preset_fs_ops[] = { 35, 34, 48, 53, 54, 78, 79, 80, 38, 276, 36, 37 };
static const int preset_network[] = { 198, 200, 201, 203, 206, 207, 208, 209, 210, 211, 212, 242 };
static const int preset_process[] = { 220, 221, 435, 93, 94, 260, 95 };
static const int preset_signal[] = { 129, 130, 131, 134, 135 };
static const int preset_memory[] = { 222, 226, 215, 216, 233, 227, 228, 229, 214 };
static const int preset_ipc[] = { 98, 99 };
static const int preset_security[] = { 277, 280, 117, 167, 146, 147 };

static int apply_preset(int preset_id) {
    const int *nrs; int count, i;
    if (preset_id == 9) { bitmap_set_all(); if (!g_tier2_hooked) install_tier2(); return 0; }
    switch (preset_id) {
    case 1: nrs = preset_file_io; count = 12; break;
    case 2: nrs = preset_fs_ops; count = 12; break;
    case 3: nrs = preset_network; count = 12; break;
    case 4: nrs = preset_process; count = 7; break;
    case 5: nrs = preset_signal; count = 5; break;
    case 6: nrs = preset_memory; count = 9; break;
    case 7: nrs = preset_ipc; count = 2; break;
    case 8: nrs = preset_security; count = 6; break;
    default: return -1;
    }
    bitmap_clear_all();
    for (i = 0; i < count; i++) bitmap_set(nrs[i]);
    return 0;
}

/* ================================================================
 * JSON output functions
 * ================================================================ */
static void emit_event_json(int *off, struct svc_event *ev, int comma) {
    char esc_comm[TASK_COMM_LEN * 4];
    char esc_desc[MAX_DESC_LEN * 2 + 4];
    char esc_caller[MAX_CALLER_INFO * 2 + 4];
    char esc_fdpath[MAX_PATH_LEN * 2 + 4];
    json_escape(esc_comm, sizeof(esc_comm), ev->comm);
    json_escape(esc_desc, sizeof(esc_desc), ev->desc);
    json_escape(esc_caller, sizeof(esc_caller), ev->caller_info);
    json_escape(esc_fdpath, sizeof(esc_fdpath), ev->fd_path);
    *off += snprintf(g_outbuf + *off, OUTBUF_SIZE - *off,
        "%s{\"seq\":%lu,\"nr\":%d,\"name\":\"%s\",\"pid\":%d,\"uid\":%d,"
        "\"comm\":\"%s\",\"a0\":%lu,\"a1\":%lu,\"a2\":%lu,"
        "\"a3\":%lu,\"a4\":%lu,\"a5\":%lu,"
        "\"desc\":\"%s\",\"caller\":\"%s\",\"callerAddr\":\"0x%lx\","
        "\"pc\":\"0x%lx\",\"fdPath\":\"%s\",\"cloneFn\":%lu}",
        comma ? "," : "",
        ev->seq, ev->nr, nr_to_name(ev->nr), ev->pid, ev->uid,
        esc_comm, ev->a0, ev->a1, ev->a2, ev->a3, ev->a4, ev->a5,
        esc_desc, esc_caller, ev->caller_addr,
        ev->pc, esc_fdpath, ev->clone_fn);
}

static int drain_events(void) {
    int i, off = 0, cnt;
    cnt = g_count;
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "{\"ok\":true,\"events\":[");
    for (i = 0; i < cnt && off < OUTBUF_SIZE - 2048; i++) {
        int ei = (g_tail + i) % MAX_EVENTS;
        emit_event_json(&off, &g_events[ei], i > 0);
    }
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "],\"total\":%lu,\"drained\":%d}", g_total, i);
    g_head = 0; g_tail = 0; g_count = 0;
    return write_output_file(OUTPUT_PATH, g_outbuf, off);
}

static int output_events(void) {
    int i, off = 0, cnt;
    cnt = g_count;
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "{\"ok\":true,\"events\":[");
    for (i = 0; i < cnt && off < OUTBUF_SIZE - 2048; i++) {
        int ei = (g_tail + i) % MAX_EVENTS;
        emit_event_json(&off, &g_events[ei], i > 0);
    }
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "],\"total\":%lu,\"buffered\":%d}", g_total, cnt);
    return write_output_file(OUTPUT_PATH, g_outbuf, off);
}

static int output_status(void) {
    int off = 0;
    char nrlist[4096];
    bitmap_list(nrlist, sizeof(nrlist));
    off = snprintf(g_outbuf, OUTBUF_SIZE,
        "{\"ok\":true,\"enabled\":%d,\"uid\":%d,\"tier2\":%d,"
        "\"eventsTotal\":%lu,\"eventsBuffered\":%d,"
        "\"nrFilter\":\"%s\",\"tier1Hooked\":%d,\"tier2Hooked\":%d,"
        "\"version\":\"9.0.0\"}",
        g_enabled, g_uid_filter, g_tier2_enabled,
        g_total, g_count, nrlist, g_tier1_hooked, g_tier2_hooked);
    return write_output_file(OUTPUT_PATH, g_outbuf, off);
}

static int str_to_int(const char *s) {
    int val = 0, neg = 0;
    if (!s) return 0;
    while (*s == ' ') s++;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') { val = val * 10 + (*s - '0'); s++; }
    return neg ? -val : val;
}

/* ================================================================
 * CTL0 command dispatcher
 * ================================================================ */
static long __attribute__((used)) kpm_control0(const char *args, char *__user out_msg, int outlen) {
    int off = 0, nr, i, val, cnt;
    char *p;

    if (!args || !*args) { snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":false,\"error\":\"no cmd\"}"); goto out; }

    if (strcmp(args, "enable") == 0) {
        g_enabled = 1;
        if (!g_tier1_hooked) install_tier1();
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"enabled\"}");
        goto out;
    }
    if (strcmp(args, "disable") == 0) {
        g_enabled = 0;
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"disabled\"}");
        goto out;
    }
    if (strcmp(args, "status") == 0) { output_status(); return 0; }
    if (strcmp(args, "drain") == 0) { drain_events(); return 0; }
    if (strcmp(args, "events") == 0) { output_events(); return 0; }
    if (strcmp(args, "clear") == 0) {
        g_head = 0; g_tail = 0; g_count = 0;
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"cleared\"}");
        goto out;
    }
    if (strncmp(args, "uid ", 4) == 0) {
        g_uid_filter = str_to_int(args + 4);
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"uid\":%d}", g_uid_filter);
        goto out;
    }
    if (strncmp(args, "enable_nr ", 10) == 0) {
        nr = str_to_int(args + 10);
        bitmap_set(nr);
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"enabled_nr\":%d}", nr);
        goto out;
    }
    if (strncmp(args, "disable_nr ", 11) == 0) {
        nr = str_to_int(args + 11);
        bitmap_clear(nr);
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"disabled_nr\":%d}", nr);
        goto out;
    }
    if (strncmp(args, "set_nrs ", 8) == 0) {
        bitmap_clear_all();
        p = (char *)(args + 8);
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if (*p >= '0' && *p <= '9') {
                nr = str_to_int(p);
                bitmap_set(nr);
                while (*p >= '0' && *p <= '9') p++;
            } else break;
        }
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"nrs_set\"}");
        goto out;
    }
    if (strcmp(args, "enable_all_nr") == 0) {
        bitmap_set_all();
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"all_enabled\"}");
        goto out;
    }
    if (strcmp(args, "disable_all_nr") == 0) {
        bitmap_clear_all();
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"all_disabled\"}");
        goto out;
    }
    if (strncmp(args, "preset ", 7) == 0) {
        val = str_to_int(args + 7);
        if (apply_preset(val) == 0)
            snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"preset\":%d}", val);
        else
            snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":false,\"error\":\"invalid preset\"}");
        goto out;
    }
    if (strncmp(args, "tier2 ", 6) == 0) {
        val = str_to_int(args + 6);
        if (val && !g_tier2_hooked) install_tier2();
        else if (!val && g_tier2_hooked) remove_tier2();
        snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"tier2\":%d}", g_tier2_enabled);
        goto out;
    }

    snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":false,\"error\":\"unknown cmd: %s\"}", args);

out:
    off = strlen(g_outbuf);
    return write_output_file(OUTPUT_PATH, g_outbuf, off);
}

/* ================================================================
 * KPM entry points
 * ================================================================ */
static long __attribute__((used)) svc_init(const char *args, const char *event, void *__user reserved) {
    (void)args; (void)event; (void)reserved;

    /* Allocate ring buffer and output buffer via kp_malloc */
    g_events = (struct svc_event *)kp_malloc(sizeof(struct svc_event) * MAX_EVENTS);
    if (!g_events) {
        pr_err("svc_monitor: failed to allocate event buffer\n");
        return -1;
    }
    g_outbuf = (char *)kp_malloc(OUTBUF_SIZE);
    if (!g_outbuf) {
        kp_free(g_events);
        pr_err("svc_monitor: failed to allocate output buffer\n");
        return -1;
    }

    memset(g_events, 0, sizeof(struct svc_event) * MAX_EVENTS);
    memset(g_outbuf, 0, OUTBUF_SIZE);
    g_head = 0; g_tail = 0; g_count = 0; g_total = 0; g_seq = 0;
    g_enabled = 0; g_uid_filter = 0;
    g_tier1_hooked = 0; g_tier2_hooked = 0; g_tier2_enabled = 0;

    init_hook_table();
    bitmap_set_all();

    pr_info("svc_monitor v9.0.0 loaded\n");
    return 0;
}

static long __attribute__((used)) svc_exit(void *__user reserved) {
    (void)reserved;
    g_enabled = 0;
    if (g_tier2_hooked) remove_tier2();
    if (g_tier1_hooked) remove_tier1();
    if (g_outbuf) { kp_free(g_outbuf); g_outbuf = 0; }
    if (g_events) { kp_free(g_events); g_events = 0; }
    pr_info("svc_monitor v9.0.0 unloaded\n");
    return 0;
}

KPM_INIT(svc_init);
KPM_CTL0(kpm_control0);
KPM_EXIT(svc_exit);
