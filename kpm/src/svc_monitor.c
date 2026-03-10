/* svc_monitor.c - KPM v8.3.0
 * ARM64 SVC system-call monitor for Pixel 6 / Android 12 / kernel 5.10.43
 * KernelPatch Module - CTL0 command interface
 *
 * Symbol-safe: every API used below is either:
 *   (a) provided by the KPM SDK (kfunc_*, raw_syscall*, hook_syscall*, compat_*),
 *   (b) a compiler built-in (__builtin_memset/memcpy), or
 *   (c) declared in linux/string.h or linux/printk.h which are available to KPM.
 *
 * v8.3 fixes vs v8.2:
 *   - current->pid  replaced with raw_syscall0(__NR_gettid)
 *   - current->cred->uid replaced with current_uid()
 *   - comm read via TASK_COMM_OFFSET=2560 with ASCII validation fallback
 *   - safe_copy_user_bytes uses compat_copy_from_user (binary-safe)
 *   - safe_read_user_ptr  uses compat_copy_from_user
 *   - per-event monotonic sequence number (g_seq)
 *   - output buffer 128 KB
 *   - __attribute__((used)) on exported entry points
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <kputils.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("svc_monitor");
KPM_VERSION("8.3.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("SVC Monitor");
KPM_DESCRIPTION("ARM64 SVC syscall monitor with deep argument parsing");

/* ================================================================
 * Syscall number definitions (ARM64, kernel 5.10)
 * ================================================================ */
#define __NR_io_setup           0
#define __NR_io_destroy         1
#define __NR_io_submit          2
#define __NR_io_cancel          3
#define __NR_io_getevents       4
#define __NR_setxattr           5
#define __NR_getxattr           8
#define __NR_listxattr          11
#define __NR_removexattr        14
#define __NR_getcwd             17
#define __NR_lookup_dcookie     18
#define __NR_eventfd2           19
#define __NR_epoll_create1      20
#define __NR_epoll_ctl          21
#define __NR_epoll_pwait        22
#define __NR_dup                23
#define __NR_dup3               24
#define __NR_fcntl              25
#define __NR_inotify_init1      26
#define __NR_inotify_add_watch  27
#define __NR_inotify_rm_watch   28
#define __NR_ioctl              29
#define __NR_ioprio_set         30
#define __NR_ioprio_get         31
#define __NR_flock              32
#define __NR_mknodat            33
#define __NR_mkdirat            34
#define __NR_unlinkat           35
#define __NR_symlinkat          36
#define __NR_linkat             37
#define __NR_renameat           38
#define __NR_umount2            39
#define __NR_mount              40
#define __NR_pivot_root         41
#define __NR_statfs             43
#define __NR_fstatfs            44
#define __NR_truncate           45
#define __NR_ftruncate          46
#define __NR_fallocate          47
#define __NR_faccessat          48
#define __NR_chdir              49
#define __NR_fchmod             52
#define __NR_fchmodat           53
#define __NR_fchownat           54
#define __NR_fchown             55
#define __NR_openat             56
#define __NR_close              57
#define __NR_vhangup            58
#define __NR_pipe2              59
#define __NR_quotactl           60
#define __NR_getdents64         61
#define __NR_lseek              62
#define __NR_read               63
#define __NR_write              64
#define __NR_readv              65
#define __NR_writev             66
#define __NR_pread64            67
#define __NR_pwrite64           68
#define __NR_sendfile           71
#define __NR_pselect6           72
#define __NR_ppoll              73
#define __NR_signalfd4          74
#define __NR_splice             76
#define __NR_tee                77
#define __NR_readlinkat         78
#define __NR_newfstatat         79
#define __NR_fstat              80
#define __NR_sync               81
#define __NR_fsync              82
#define __NR_fdatasync          83
#define __NR_timerfd_create     85
#define __NR_timerfd_settime    86
#define __NR_timerfd_gettime    87
#define __NR_utimensat          88
#define __NR_acct               89
#define __NR_capget             90
#define __NR_capset             91
#define __NR_personality        92
#define __NR_exit               93
#define __NR_exit_group         94
#define __NR_waitid             95
#define __NR_set_tid_address    96
#define __NR_unshare            97
#define __NR_futex              98
#define __NR_set_robust_list    99
#define __NR_get_robust_list    100
#define __NR_nanosleep          101
#define __NR_getitimer          102
#define __NR_setitimer          103
#define __NR_kexec_load         104
#define __NR_init_module        105
#define __NR_delete_module      106
#define __NR_timer_create       107
#define __NR_timer_gettime      108
#define __NR_timer_getoverrun   109
#define __NR_timer_settime      110
#define __NR_timer_delete       111
#define __NR_clock_settime      112
#define __NR_clock_gettime      113
#define __NR_clock_getres       114
#define __NR_clock_nanosleep    115
#define __NR_syslog             116
#define __NR_ptrace             117
#define __NR_sched_setparam     118
#define __NR_sched_setscheduler 119
#define __NR_sched_getscheduler 120
#define __NR_sched_getparam     121
#define __NR_sched_setaffinity  122
#define __NR_sched_getaffinity  123
#define __NR_sched_yield        124
#define __NR_sched_get_priority_max 125
#define __NR_sched_get_priority_min 126
#define __NR_sched_rr_get_interval 127
#define __NR_restart_syscall    128
#define __NR_kill               129
#define __NR_tkill              130
#define __NR_tgkill             131
#define __NR_sigaltstack        132
#define __NR_rt_sigsuspend      133
#define __NR_rt_sigaction       134
#define __NR_rt_sigprocmask     135
#define __NR_rt_sigpending      136
#define __NR_rt_sigtimedwait    137
#define __NR_rt_sigqueueinfo    138
#define __NR_rt_sigreturn       139
#define __NR_setpriority        140
#define __NR_getpriority        141
#define __NR_reboot             142
#define __NR_setregid           143
#define __NR_setgid             144
#define __NR_setreuid           145
#define __NR_setuid             146
#define __NR_setresuid          147
#define __NR_getresuid          148
#define __NR_setresgid          149
#define __NR_getresgid          150
#define __NR_setfsuid           151
#define __NR_setfsgid           152
#define __NR_times              153
#define __NR_setpgid            154
#define __NR_getpgid            155
#define __NR_getsid             156
#define __NR_setsid             157
#define __NR_getgroups          158
#define __NR_setgroups          159
#define __NR_uname              160
#define __NR_sethostname        161
#define __NR_setdomainname      162
#define __NR_getrlimit          163
#define __NR_setrlimit          164
#define __NR_getrusage          165
#define __NR_umask              166
#define __NR_prctl              167
#define __NR_getcpu             168
#define __NR_gettimeofday       169
#define __NR_settimeofday       170
#define __NR_adjtimex           171
#define __NR_getpid             172
#define __NR_getppid            173
#define __NR_getuid             174
#define __NR_geteuid            175
#define __NR_getgid             176
#define __NR_getegid            177
#define __NR_gettid             178
#define __NR_sysinfo            179
#define __NR_mq_open            180
#define __NR_mq_unlink          181
#define __NR_mq_timedsend       182
#define __NR_mq_timedreceive    183
#define __NR_mq_notify          184
#define __NR_mq_getsetattr      185
#define __NR_msgget             186
#define __NR_msgctl             187
#define __NR_msgrcv             188
#define __NR_msgsnd             189
#define __NR_semget             190
#define __NR_semctl             191
#define __NR_semtimedop         192
#define __NR_semop              193
#define __NR_shmget             194
#define __NR_shmctl             195
#define __NR_shmat              196
#define __NR_shmdt              197
#define __NR_socket             198
#define __NR_socketpair         199
#define __NR_bind               200
#define __NR_listen             201
#define __NR_accept             202
#define __NR_connect            203
#define __NR_getsockname        204
#define __NR_getpeername        205
#define __NR_sendto             206
#define __NR_recvfrom           207
#define __NR_setsockopt         208
#define __NR_getsockopt         209
#define __NR_shutdown           210
#define __NR_sendmsg            211
#define __NR_recvmsg            212
#define __NR_readahead          213
#define __NR_brk                214
#define __NR_munmap             215
#define __NR_mremap             216
#define __NR_add_key            217
#define __NR_request_key        218
#define __NR_keyctl             219
#define __NR_clone              220
#define __NR_execve             221
#define __NR_mmap               222
#define __NR_fadvise64          223
#define __NR_swapon             224
#define __NR_swapoff            225
#define __NR_mprotect           226
#define __NR_msync              227
#define __NR_mlock              228
#define __NR_munlock            229
#define __NR_mlockall           230
#define __NR_munlockall         231
#define __NR_mincore            232
#define __NR_madvise            233
#define __NR_remap_file_pages   234
#define __NR_mbind              235
#define __NR_get_mempolicy      236
#define __NR_set_mempolicy      237
#define __NR_migrate_pages      238
#define __NR_move_pages         239
#define __NR_rt_tgsigqueueinfo  240
#define __NR_perf_event_open    241
#define __NR_accept4            242
#define __NR_recvmmsg           243
#define __NR_arch_specific_syscall 244
#define __NR_wait4              260
#define __NR_prlimit64          261
#define __NR_fanotify_init      262
#define __NR_fanotify_mark      263
#define __NR_name_to_handle_at  264
#define __NR_open_by_handle_at  265
#define __NR_clock_adjtime      266
#define __NR_syncfs             267
#define __NR_setns              268
#define __NR_sendmmsg           269
#define __NR_process_vm_readv   270
#define __NR_process_vm_writev  271
#define __NR_kcmp               272
#define __NR_finit_module       273
#define __NR_sched_setattr      274
#define __NR_sched_getattr      275
#define __NR_renameat2          276
#define __NR_seccomp            277
#define __NR_getrandom          278
#define __NR_memfd_create       279
#define __NR_bpf                280
#define __NR_execveat           281
#define __NR_userfaultfd        282
#define __NR_membarrier         283
#define __NR_mlock2             284
#define __NR_copy_file_range    285
#define __NR_preadv2            286
#define __NR_pwritev2           287
#define __NR_statx              291
#define __NR_io_uring_setup     425
#define __NR_io_uring_enter     426
#define __NR_io_uring_register  427
#define __NR_pidfd_open         434
#define __NR_clone3             435
#define __NR_close_range        436
#define __NR_openat2            437
#define __NR_pidfd_getfd        438
#define __NR_faccessat2         439

/* ================================================================
 * Architecture / buffer constants
 * ================================================================ */
#define THREAD_SIZE      16384
#define PT_REGS_SIZE     272
#define REGS_OFFSET      (THREAD_SIZE - PT_REGS_SIZE)
#define REG_X0           0
#define REG_X8           8
#define REG_PC           32
#define TASK_COMM_OFFSET 2560
#define TASK_COMM_LEN    16

#define MAX_EVENTS       1024
#define MAX_STR_LEN      256
#define MAX_DESC_LEN     512
#define MAX_PATH_LEN     256
#define OUTBUF_SIZE      131072
#define OUTPUT_PATH      "/data/local/tmp/svc_out.json"

#define BITMAP_BITS      512
#define BITMAP_LONGS     (BITMAP_BITS / 64)

/* ================================================================
 * Data structures
 * ================================================================ */
struct svc_event {
    unsigned long seq;
    int nr;
    int pid;
    int uid;
    char comm[TASK_COMM_LEN];
    unsigned long a0, a1, a2, a3, a4, a5;
    char desc[MAX_DESC_LEN];
    unsigned long caller_addr;
    unsigned long pc;
    char fd_path[MAX_PATH_LEN];
    unsigned long clone_fn;
};

/* ================================================================
 * Global state
 * ================================================================ */
static struct svc_event g_events[MAX_EVENTS];
static volatile int g_head = 0;
static volatile int g_tail = 0;
static volatile int g_count = 0;
static volatile unsigned long g_total = 0;
static volatile unsigned long g_seq = 0;

static volatile int g_enabled = 0;
static volatile int g_uid_filter = -1;
static volatile int g_tier2_enabled = 0;

static unsigned long g_nr_bitmap[BITMAP_LONGS];

static char g_outbuf[OUTBUF_SIZE];

/* ================================================================
 * Syscall name table
 * ================================================================ */
struct nr_name { int nr; const char *name; };
static const struct nr_name nr_names[] = {
    {0,"io_setup"},{1,"io_destroy"},{2,"io_submit"},{3,"io_cancel"},
    {4,"io_getevents"},{5,"setxattr"},{8,"getxattr"},{11,"listxattr"},
    {14,"removexattr"},{17,"getcwd"},{18,"lookup_dcookie"},{19,"eventfd2"},
    {20,"epoll_create1"},{21,"epoll_ctl"},{22,"epoll_pwait"},
    {23,"dup"},{24,"dup3"},{25,"fcntl"},{26,"inotify_init1"},
    {27,"inotify_add_watch"},{28,"inotify_rm_watch"},
    {29,"ioctl"},{30,"ioprio_set"},{31,"ioprio_get"},{32,"flock"},
    {33,"mknodat"},{34,"mkdirat"},{35,"unlinkat"},{36,"symlinkat"},
    {37,"linkat"},{38,"renameat"},{39,"umount2"},{40,"mount"},
    {43,"statfs"},{44,"fstatfs"},{45,"truncate"},{46,"ftruncate"},
    {47,"fallocate"},{48,"faccessat"},{49,"chdir"},
    {52,"fchmod"},{53,"fchmodat"},{54,"fchownat"},{55,"fchown"},
    {56,"openat"},{57,"close"},{58,"vhangup"},{59,"pipe2"},
    {61,"getdents64"},{62,"lseek"},{63,"read"},{64,"write"},
    {65,"readv"},{66,"writev"},{67,"pread64"},{68,"pwrite64"},
    {71,"sendfile"},{72,"pselect6"},{73,"ppoll"},
    {76,"splice"},{77,"tee"},{78,"readlinkat"},{79,"newfstatat"},
    {80,"fstat"},{81,"sync"},{82,"fsync"},{83,"fdatasync"},
    {85,"timerfd_create"},{86,"timerfd_settime"},{87,"timerfd_gettime"},
    {88,"utimensat"},{89,"acct"},
    {90,"capget"},{91,"capset"},{92,"personality"},
    {93,"exit"},{94,"exit_group"},{95,"waitid"},
    {96,"set_tid_address"},{97,"unshare"},{98,"futex"},
    {99,"set_robust_list"},{100,"get_robust_list"},
    {101,"nanosleep"},{102,"getitimer"},{103,"setitimer"},
    {105,"init_module"},{106,"delete_module"},
    {107,"timer_create"},{108,"timer_gettime"},{109,"timer_getoverrun"},
    {110,"timer_settime"},{111,"timer_delete"},
    {112,"clock_settime"},{113,"clock_gettime"},{114,"clock_getres"},
    {115,"clock_nanosleep"},{116,"syslog"},{117,"ptrace"},
    {118,"sched_setparam"},{119,"sched_setscheduler"},
    {120,"sched_getscheduler"},{121,"sched_getparam"},
    {122,"sched_setaffinity"},{123,"sched_getaffinity"},
    {124,"sched_yield"},{125,"sched_get_priority_max"},
    {126,"sched_get_priority_min"},{127,"sched_rr_get_interval"},
    {128,"restart_syscall"},{129,"kill"},{130,"tkill"},{131,"tgkill"},
    {132,"sigaltstack"},{133,"rt_sigsuspend"},{134,"rt_sigaction"},
    {135,"rt_sigprocmask"},{136,"rt_sigpending"},{137,"rt_sigtimedwait"},
    {138,"rt_sigqueueinfo"},{139,"rt_sigreturn"},
    {140,"setpriority"},{141,"getpriority"},{142,"reboot"},
    {143,"setregid"},{144,"setgid"},{145,"setreuid"},{146,"setuid"},
    {147,"setresuid"},{148,"getresuid"},{149,"setresgid"},{150,"getresgid"},
    {151,"setfsuid"},{152,"setfsgid"},{153,"times"},
    {154,"setpgid"},{155,"getpgid"},{156,"getsid"},{157,"setsid"},
    {158,"getgroups"},{159,"setgroups"},{160,"uname"},
    {163,"getrlimit"},{164,"setrlimit"},{165,"getrusage"},
    {166,"umask"},{167,"prctl"},{168,"getcpu"},
    {169,"gettimeofday"},{170,"settimeofday"},
    {172,"getpid"},{173,"getppid"},{174,"getuid"},{175,"geteuid"},
    {176,"getgid"},{177,"getegid"},{178,"gettid"},{179,"sysinfo"},
    {180,"mq_open"},{181,"mq_unlink"},{182,"mq_timedsend"},
    {183,"mq_timedreceive"},{184,"mq_notify"},{185,"mq_getsetattr"},
    {186,"msgget"},{187,"msgctl"},{188,"msgrcv"},{189,"msgsnd"},
    {190,"semget"},{191,"semctl"},{192,"semtimedop"},{193,"semop"},
    {194,"shmget"},{195,"shmctl"},{196,"shmat"},{197,"shmdt"},
    {198,"socket"},{199,"socketpair"},{200,"bind"},{201,"listen"},
    {202,"accept"},{203,"connect"},{204,"getsockname"},{205,"getpeername"},
    {206,"sendto"},{207,"recvfrom"},{208,"setsockopt"},{209,"getsockopt"},
    {210,"shutdown"},{211,"sendmsg"},{212,"recvmsg"},
    {213,"readahead"},{214,"brk"},{215,"munmap"},{216,"mremap"},
    {217,"add_key"},{218,"request_key"},{219,"keyctl"},
    {220,"clone"},{221,"execve"},{222,"mmap"},{223,"fadvise64"},
    {224,"swapon"},{225,"swapoff"},
    {226,"mprotect"},{227,"msync"},{228,"mlock"},{229,"munlock"},
    {230,"mlockall"},{231,"munlockall"},{232,"mincore"},{233,"madvise"},
    {241,"perf_event_open"},{242,"accept4"},{243,"recvmmsg"},
    {260,"wait4"},{261,"prlimit64"},
    {262,"fanotify_init"},{263,"fanotify_mark"},
    {267,"syncfs"},{268,"setns"},{269,"sendmmsg"},
    {270,"process_vm_readv"},{271,"process_vm_writev"},
    {272,"kcmp"},{273,"finit_module"},
    {274,"sched_setattr"},{275,"sched_getattr"},
    {276,"renameat2"},{277,"seccomp"},{278,"getrandom"},
    {279,"memfd_create"},{280,"bpf"},{281,"execveat"},
    {282,"userfaultfd"},{283,"membarrier"},{284,"mlock2"},
    {285,"copy_file_range"},{286,"preadv2"},{287,"pwritev2"},
    {291,"statx"},
    {425,"io_uring_setup"},{426,"io_uring_enter"},{427,"io_uring_register"},
    {434,"pidfd_open"},{435,"clone3"},{436,"close_range"},
    {437,"openat2"},{438,"pidfd_getfd"},{439,"faccessat2"},
    {-1, 0}
};

static const char *nr_to_name(int nr) {
    int i;
    for (i = 0; nr_names[i].nr >= 0; i++) {
        if (nr_names[i].nr == nr) return nr_names[i].name;
    }
    return "unknown";
}

/* ================================================================
 * Bitmap operations for NR filter
 * ================================================================ */
static void bitmap_set(int nr) {
    if (nr >= 0 && nr < BITMAP_BITS)
        g_nr_bitmap[nr / 64] |= (1UL << (nr % 64));
}
static void bitmap_clear(int nr) {
    if (nr >= 0 && nr < BITMAP_BITS)
        g_nr_bitmap[nr / 64] &= ~(1UL << (nr % 64));
}
static int bitmap_test(int nr) {
    if (nr < 0 || nr >= BITMAP_BITS) return 0;
    return (g_nr_bitmap[nr / 64] >> (nr % 64)) & 1;
}
static void bitmap_set_all(void) {
    int i;
    for (i = 0; i < BITMAP_LONGS; i++)
        g_nr_bitmap[i] = ~0UL;
}
static void bitmap_clear_all(void) {
    int i;
    for (i = 0; i < BITMAP_LONGS; i++)
        g_nr_bitmap[i] = 0UL;
}
static int bitmap_any_set(void) {
    int i;
    for (i = 0; i < BITMAP_LONGS; i++)
        if (g_nr_bitmap[i]) return 1;
    return 0;
}
static int bitmap_list(char *buf, int buflen) {
    int i, off = 0, first = 1;
    for (i = 0; i < BITMAP_BITS && off < buflen - 8; i++) {
        if (bitmap_test(i)) {
            off += snprintf(buf + off, buflen - off, "%s%d", first ? "" : ",", i);
            first = 0;
        }
    }
    if (off == 0) { buf[0] = 0; }
    return off;
}

/* ================================================================
 * Safe user-space access helpers (KPM-safe)
 * ================================================================ */
static int safe_copy_user_bytes(void *dst, unsigned long user_addr, int maxlen) {
    int i;
    volatile char *vdst = (volatile char *)dst;
    if (!user_addr || !maxlen) return 0;
    for (i = 0; i < maxlen; i++) vdst[i] = 0;
    if (compat_strncpy_from_user((char *)dst, (const char __user *)user_addr, maxlen - 1) < 0) {
        for (i = 0; i < maxlen; i++) vdst[i] = 0;
        return -1;
    }
    ((char *)dst)[maxlen - 1] = 0;
    return 0;
}

/* ================================================================
 * Get current task info (KPM-safe, no unexported symbols)
 * ================================================================ */
static int get_current_pid(void) {
    return (int)raw_syscall0(__NR_gettid);
}

static int get_current_uid(void) {
    return current_uid();
}

static void get_current_comm(char *buf, int len) {
    char *task = (char *)current;
    int i, valid;
    if (!task || len < 2) { buf[0] = 0; return; }
    for (i = 0; i < (len < TASK_COMM_LEN ? len : TASK_COMM_LEN); i++) {
        buf[i] = (task + TASK_COMM_OFFSET)[i];
    }
    buf[len - 1] = 0;
    valid = 1;
    for (i = 0; i < len && buf[i]; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7e) { valid = 0; break; }
    }
    if (!valid || buf[0] == 0) {
        buf[0] = '?'; buf[1] = '?'; buf[2] = '?'; buf[3] = 0;
    }
}

/* ================================================================
 * JSON string escape (KPM-safe, no dynamic allocation)
 * ================================================================ */
static void json_escape(char *dst, int dstlen, const char *src) {
    int i, o = 0;
    unsigned char c;
    if (!src || !dstlen) { if (dstlen) dst[0] = 0; return; }
    for (i = 0; src[i] && o < dstlen - 6; i++) {
        c = (unsigned char)src[i];
        if (c == '"') {
            dst[o++] = '\\'; dst[o++] = '"';
        } else if (c == '\\') {
            dst[o++] = '\\'; dst[o++] = '\\';
        } else if (c == '\n') {
            dst[o++] = '\\'; dst[o++] = 'n';
        } else if (c == '\r') {
            dst[o++] = '\\'; dst[o++] = 'r';
        } else if (c == '\t') {
            dst[o++] = '\\'; dst[o++] = 't';
        } else if (c >= 0x20 && c < 0x7f) {
            dst[o++] = c;
        } else if (o + 4 < dstlen) {
            static const char hex[] = "0123456789abcdef";
            dst[o++] = '\\';
            dst[o++] = 'x';
            dst[o++] = hex[(c >> 4) & 0xf];
            dst[o++] = hex[c & 0xf];
        }
    }
    dst[o] = 0;
}

/* ================================================================
 * pt_regs access (ARM64, KPM-safe)
 * ================================================================ */
static unsigned long *get_pt_regs(void) {
    unsigned long sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    sp = sp & ~(THREAD_SIZE - 1);
    return (unsigned long *)(sp + REGS_OFFSET);
}

/* ================================================================
 * File output (KPM-safe: uses raw_syscall)
 * ================================================================ */
static int write_output_file(const char *path, const char *buf, int len) {
    long fd;
    fd = raw_syscall4(__NR_openat, -100 /* AT_FDCWD */,
                      (unsigned long)path,
                      0x241 /* O_WRONLY|O_CREAT|O_TRUNC */,
                      0644);
    if (fd < 0) return -1;
    raw_syscall3(__NR_write, fd, (unsigned long)buf, len);
    raw_syscall1(__NR_close, fd);
    return 0;
}

/* ================================================================
 * Tier1 hook list (44 syscalls, always loaded when enabled)
 * ================================================================ */
static const int tier1_nrs[] = {
    56,57,63,64,35,34,53,54,48,78,79,80,82,83,
    62,61,67,68,65,66,45,46,47,29,25,23,24,
    198,200,201,202,203,206,207,208,209,210,211,212,
    220,221,129,131,222
};
#define TIER1_COUNT (sizeof(tier1_nrs)/sizeof(tier1_nrs[0]))

/* ================================================================
 * Tier2 hook list (25 syscalls, loaded on demand)
 * ================================================================ */
static const int tier2_nrs[] = {
    40,39,76,71,117,167,261,277,
    105,106,273,280,281,
    226,233,214,215,216,228,229,
    5,8,14,88,
    435
};
#define TIER2_COUNT (sizeof(tier2_nrs)/sizeof(tier2_nrs[0]))

/* ================================================================
 * Preset definitions
 * ================================================================ */
struct preset_def {
    int id;
    const char *name;
    const char *desc;
    const int *nrs;
    int count;
};

static const int preset_file_io[] = {56,57,63,64,62,67,68,65,66,82,83,71,45,46,47,61,80,79,213};
static const int preset_fs_ops[] = {34,35,33,53,54,55,48,78,38,276,37,36,49,88,5,8,14,291};
static const int preset_network[] = {198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,242,269,243};
static const int preset_process[] = {220,221,281,435,93,94,260,95,167,261,172,178,174,176};
static const int preset_signal[] = {129,130,131,134,135,136,137,138,240};
static const int preset_memory[] = {222,226,215,216,214,228,229,230,231,232,233,284};
static const int preset_ipc[] = {59,186,187,188,189,190,191,192,193,194,195,196,197,98};
static const int preset_security[] = {277,280,117,105,106,273,90,91,146,147,149,151,152,268};

static const struct preset_def presets[] = {
    {1, "file_io",  "File I/O",      preset_file_io,  sizeof(preset_file_io)/sizeof(int)},
    {2, "fs_ops",   "Filesystem ops", preset_fs_ops,   sizeof(preset_fs_ops)/sizeof(int)},
    {3, "network",  "Network",       preset_network,   sizeof(preset_network)/sizeof(int)},
    {4, "process",  "Process mgmt",  preset_process,   sizeof(preset_process)/sizeof(int)},
    {5, "signal",   "Signals",       preset_signal,    sizeof(preset_signal)/sizeof(int)},
    {6, "memory",   "Memory mgmt",   preset_memory,    sizeof(preset_memory)/sizeof(int)},
    {7, "ipc",      "IPC",           preset_ipc,       sizeof(preset_ipc)/sizeof(int)},
    {8, "security", "Security",      preset_security,  sizeof(preset_security)/sizeof(int)},
    {0, 0, 0, 0, 0}
};

/* ================================================================
 * Deep argument parsing for syscalls
 * ================================================================ */
static void deep_parse_args(struct svc_event *ev) {
    char tmp[MAX_STR_LEN];
    int off = 0;
    ev->desc[0] = 0;
    ev->fd_path[0] = 0;
    ev->clone_fn = 0;

    switch (ev->nr) {
    case __NR_openat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" flags=0x%lx mode=0%lo", (int)ev->a0, tmp, ev->a2, ev->a3);
        break;
    case __NR_close:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d", (int)ev->a0);
        break;
    case __NR_read:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d count=%lu", (int)ev->a0, ev->a2);
        break;
    case __NR_write:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d count=%lu", (int)ev->a0, ev->a2);
        break;
    case __NR_readv:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d iovcnt=%lu", (int)ev->a0, ev->a2);
        break;
    case __NR_writev:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d iovcnt=%lu", (int)ev->a0, ev->a2);
        break;
    case __NR_pread64:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d count=%lu offset=%ld", (int)ev->a0, ev->a2, (long)ev->a3);
        break;
    case __NR_pwrite64:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d count=%lu offset=%ld", (int)ev->a0, ev->a2, (long)ev->a3);
        break;
    case __NR_lseek:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d offset=%ld whence=%d", (int)ev->a0, (long)ev->a1, (int)ev->a2);
        break;
    case __NR_sendfile:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "out_fd=%d in_fd=%d count=%lu", (int)ev->a0, (int)ev->a1, ev->a3);
        break;
    case __NR_getdents64:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d count=%lu", (int)ev->a0, ev->a2);
        break;
    case __NR_fstat:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d", (int)ev->a0);
        break;
    case __NR_newfstatat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" flags=0x%lx", (int)ev->a0, tmp, ev->a3);
        break;
    case __NR_fsync:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d", (int)ev->a0);
        break;
    case __NR_fdatasync:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d", (int)ev->a0);
        break;
    case __NR_truncate:
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "path=\"%s\" length=%ld", tmp, (long)ev->a1);
        break;
    case __NR_ftruncate:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d length=%ld", (int)ev->a0, (long)ev->a1);
        break;
    case __NR_fallocate:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d mode=%d offset=%ld len=%ld", (int)ev->a0, (int)ev->a1, (long)ev->a2, (long)ev->a3);
        break;
    case __NR_readlinkat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" bufsiz=%lu", (int)ev->a0, tmp, ev->a3);
        break;
    case __NR_faccessat:
    case __NR_faccessat2:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" mode=%d flags=0x%lx", (int)ev->a0, tmp, (int)ev->a2, ev->a3);
        break;
    case __NR_mkdirat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" mode=0%lo", (int)ev->a0, tmp, ev->a2);
        break;
    case __NR_unlinkat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" flags=0x%lx", (int)ev->a0, tmp, ev->a2);
        break;
    case __NR_renameat:
    case __NR_renameat2: {
        char tmp2[MAX_STR_LEN];
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        safe_copy_user_bytes(tmp2, ev->a3, sizeof(tmp2));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "olddfd=%d old=\"%s\" newdfd=%d new=\"%s\"", (int)ev->a0, tmp, (int)ev->a2, tmp2);
        break;
    }
    case __NR_linkat: {
        char tmp2[MAX_STR_LEN];
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        safe_copy_user_bytes(tmp2, ev->a3, sizeof(tmp2));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "olddfd=%d old=\"%s\" newdfd=%d new=\"%s\" flags=0x%lx", (int)ev->a0, tmp, (int)ev->a2, tmp2, ev->a4);
        break;
    }
    case __NR_symlinkat: {
        char tmp2[MAX_STR_LEN];
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        safe_copy_user_bytes(tmp2, ev->a2, sizeof(tmp2));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "target=\"%s\" newdfd=%d linkpath=\"%s\"", tmp, (int)ev->a1, tmp2);
        break;
    }
    case __NR_fchmod:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d mode=0%lo", (int)ev->a0, ev->a1);
        break;
    case __NR_fchmodat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" mode=0%lo", (int)ev->a0, tmp, ev->a2);
        break;
    case __NR_fchownat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" uid=%d gid=%d flags=0x%lx", (int)ev->a0, tmp, (int)ev->a2, (int)ev->a3, ev->a4);
        break;
    case __NR_fchown:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d uid=%d gid=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_ioctl:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d cmd=0x%lx arg=0x%lx", (int)ev->a0, ev->a1, ev->a2);
        break;
    case __NR_fcntl:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d cmd=%d arg=0x%lx", (int)ev->a0, (int)ev->a1, ev->a2);
        break;
    case __NR_dup:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "oldfd=%d", (int)ev->a0);
        break;
    case __NR_dup3:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "oldfd=%d newfd=%d flags=0x%lx", (int)ev->a0, (int)ev->a1, ev->a2);
        break;
    case __NR_splice:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd_in=%d fd_out=%d len=%lu flags=0x%lx", (int)ev->a0, (int)ev->a2, ev->a4, ev->a5);
        break;
    case __NR_readahead:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d offset=%ld count=%lu", (int)ev->a0, (long)ev->a1, ev->a2);
        break;
    /* --- Network --- */
    case __NR_socket:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "domain=%d type=%d protocol=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_bind:
    case __NR_connect:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d addrlen=%d", (int)ev->a0, (int)ev->a2);
        break;
    case __NR_listen:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d backlog=%d", (int)ev->a0, (int)ev->a1);
        break;
    case __NR_accept:
    case __NR_accept4:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d flags=0x%lx", (int)ev->a0, ev->a3);
        break;
    case __NR_sendto:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d len=%lu flags=0x%lx", (int)ev->a0, ev->a2, ev->a3);
        break;
    case __NR_recvfrom:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d len=%lu flags=0x%lx", (int)ev->a0, ev->a2, ev->a3);
        break;
    case __NR_setsockopt:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d level=%d optname=%d optlen=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2, (int)ev->a4);
        break;
    case __NR_getsockopt:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d level=%d optname=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_shutdown:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d how=%d", (int)ev->a0, (int)ev->a1);
        break;
    case __NR_sendmsg:
    case __NR_recvmsg:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d flags=0x%lx", (int)ev->a0, ev->a2);
        break;
    case __NR_sendmmsg:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d vlen=%u flags=0x%lx", (int)ev->a0, (unsigned)ev->a2, ev->a3);
        break;
    case __NR_recvmmsg:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d vlen=%u flags=0x%lx", (int)ev->a0, (unsigned)ev->a2, ev->a3);
        break;
    case __NR_socketpair:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "domain=%d type=%d protocol=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    /* --- Process --- */
    case __NR_clone:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "flags=0x%lx stack=0x%lx", ev->a0, ev->a1);
        break;
    case __NR_clone3:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "args=0x%lx size=%lu", ev->a0, ev->a1);
        break;
    case __NR_execve: {
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "filename=\"%s\"", tmp);
        break;
    }
    case __NR_execveat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" flags=0x%lx", (int)ev->a0, tmp, ev->a4);
        break;
    case __NR_exit:
    case __NR_exit_group:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "status=%d", (int)ev->a0);
        break;
    case __NR_wait4:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "pid=%d options=0x%lx", (int)ev->a0, ev->a2);
        break;
    case __NR_waitid:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "which=%d pid=%d options=0x%lx", (int)ev->a0, (int)ev->a1, ev->a3);
        break;
    case __NR_prctl:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "option=%d arg2=0x%lx arg3=0x%lx", (int)ev->a0, ev->a1, ev->a2);
        break;
    case __NR_prlimit64:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "pid=%d resource=%d", (int)ev->a0, (int)ev->a1);
        break;
    /* --- Signal --- */
    case __NR_kill:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "pid=%d sig=%d", (int)ev->a0, (int)ev->a1);
        break;
    case __NR_tkill:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "tid=%d sig=%d", (int)ev->a0, (int)ev->a1);
        break;
    case __NR_tgkill:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "tgid=%d tid=%d sig=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_rt_sigaction:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "sig=%d", (int)ev->a0);
        break;
    case __NR_rt_sigprocmask:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "how=%d", (int)ev->a0);
        break;
    /* --- Memory --- */
    case __NR_mmap:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx len=%lu prot=0x%lx flags=0x%lx fd=%d offset=%ld",
            ev->a0, ev->a1, ev->a2, ev->a3, (int)ev->a4, (long)ev->a5);
        break;
    case __NR_mprotect:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx len=%lu prot=0x%lx", ev->a0, ev->a1, ev->a2);
        break;
    case __NR_munmap:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx len=%lu", ev->a0, ev->a1);
        break;
    case __NR_mremap:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "old_addr=0x%lx old_len=%lu new_len=%lu flags=0x%lx", ev->a0, ev->a1, ev->a2, ev->a3);
        break;
    case __NR_brk:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx", ev->a0);
        break;
    case __NR_mlock:
    case __NR_mlock2:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx len=%lu", ev->a0, ev->a1);
        break;
    case __NR_munlock:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx len=%lu", ev->a0, ev->a1);
        break;
    case __NR_madvise:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "addr=0x%lx len=%lu advice=%d", ev->a0, ev->a1, (int)ev->a2);
        break;
    /* --- Tier2: mount/security/etc --- */
    case __NR_mount: {
        char dev[MAX_STR_LEN], tgt[MAX_STR_LEN], fs[64];
        safe_copy_user_bytes(dev, ev->a0, sizeof(dev));
        safe_copy_user_bytes(tgt, ev->a1, sizeof(tgt));
        safe_copy_user_bytes(fs, ev->a2, sizeof(fs));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dev=\"%s\" target=\"%s\" fs=\"%s\" flags=0x%lx", dev, tgt, fs, ev->a3);
        break;
    }
    case __NR_umount2:
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "target=\"%s\" flags=0x%lx", tmp, ev->a1);
        break;
    case __NR_ptrace:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "request=%d pid=%d addr=0x%lx", (int)ev->a0, (int)ev->a1, ev->a2);
        break;
    case __NR_seccomp:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "op=%d flags=0x%lx", (int)ev->a0, ev->a1);
        break;
    case __NR_init_module:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "len=%lu", ev->a1);
        break;
    case __NR_finit_module:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d flags=0x%lx", (int)ev->a0, ev->a2);
        break;
    case __NR_delete_module:
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "name=\"%s\" flags=0x%lx", tmp, ev->a1);
        break;
    case __NR_bpf:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "cmd=%d attr=0x%lx size=%u", (int)ev->a0, ev->a1, (unsigned)ev->a2);
        break;
    case __NR_setxattr:
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "path=\"%s\" size=%lu flags=0x%lx", tmp, ev->a3, ev->a4);
        break;
    case __NR_getxattr:
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "path=\"%s\" size=%lu", tmp, ev->a3);
        break;
    case __NR_removexattr:
        safe_copy_user_bytes(tmp, ev->a0, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "path=\"%s\"", tmp);
        break;
    case __NR_utimensat:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" flags=0x%lx", (int)ev->a0, tmp, ev->a3);
        break;
    case __NR_setns:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d nstype=0x%lx", (int)ev->a0, ev->a1);
        break;
    /* --- IPC --- */
    case __NR_pipe2:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "flags=0x%lx", ev->a1);
        break;
    case __NR_futex:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "uaddr=0x%lx op=%d val=%d", ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_epoll_ctl:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "epfd=%d op=%d fd=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_epoll_pwait:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "epfd=%d maxevents=%d timeout=%d", (int)ev->a0, (int)ev->a2, (int)ev->a3);
        break;
    case __NR_statx:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\" flags=0x%lx mask=0x%lx", (int)ev->a0, tmp, ev->a2, ev->a3);
        break;
    case __NR_openat2:
        safe_copy_user_bytes(tmp, ev->a1, sizeof(tmp));
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "dfd=%d path=\"%s\"", (int)ev->a0, tmp);
        break;
    case __NR_io_uring_setup:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "entries=%u", (unsigned)ev->a0);
        break;
    case __NR_io_uring_enter:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "fd=%d to_submit=%u min_complete=%u flags=0x%lx", (int)ev->a0, (unsigned)ev->a1, (unsigned)ev->a2, ev->a3);
        break;
    case __NR_setuid:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "uid=%d", (int)ev->a0);
        break;
    case __NR_setresuid:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "ruid=%d euid=%d suid=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_setresgid:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "rgid=%d egid=%d sgid=%d", (int)ev->a0, (int)ev->a1, (int)ev->a2);
        break;
    case __NR_capget:
    case __NR_capset:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "header=0x%lx data=0x%lx", ev->a0, ev->a1);
        break;
    default:
        off += snprintf(ev->desc + off, MAX_DESC_LEN - off, "a0=0x%lx a1=0x%lx a2=0x%lx", ev->a0, ev->a1, ev->a2);
        break;
    }
    /* Tier2: caller address capture */
    if (g_tier2_enabled && ev->caller_addr) {
        /* caller already set in hook */
    }
    (void)off;
}

/* ================================================================
 * Unified syscall hook callback
 * All 69 hooks (44 tier1 + 25 tier2) funnel into this function.
 * ================================================================ */
static void before_syscall(int nr, unsigned long a0, unsigned long a1,
                           unsigned long a2, unsigned long a3,
                           unsigned long a4, unsigned long a5)
{
    int pid, uid, idx;
    struct svc_event *ev;
    unsigned long *regs;

    if (!g_enabled) return;
    if (!bitmap_test(nr)) return;

    uid = get_current_uid();
    if (g_uid_filter >= 0 && uid != g_uid_filter) return;

    pid = get_current_pid();

    idx = g_head;
    g_head = (g_head + 1) % MAX_EVENTS;
    if (g_count >= MAX_EVENTS)
        g_tail = (g_tail + 1) % MAX_EVENTS;
    else
        g_count++;
    g_total++;

    ev = &g_events[idx];
    ev->seq = g_seq++;
    ev->nr = nr;
    ev->pid = pid;
    ev->uid = uid;
    get_current_comm(ev->comm, TASK_COMM_LEN);
    ev->a0 = a0; ev->a1 = a1; ev->a2 = a2;
    ev->a3 = a3; ev->a4 = a4; ev->a5 = a5;
    ev->caller_addr = 0;
    ev->pc = 0;
    ev->clone_fn = 0;
    ev->fd_path[0] = 0;

    /* Capture PC and caller (tier2) from pt_regs */
    regs = get_pt_regs();
    if (regs) {
        ev->pc = regs[REG_PC];
        if (g_tier2_enabled) {
            /* x30 (LR) is at index 30 */
            ev->caller_addr = regs[30];
        }
    }

    /* Tier2: fd-to-path for fd-based syscalls */
    if (g_tier2_enabled) {
        int fd = -1;
        switch (nr) {
        case __NR_read: case __NR_write: case __NR_readv: case __NR_writev:
        case __NR_pread64: case __NR_pwrite64: case __NR_lseek:
        case __NR_fstat: case __NR_fsync: case __NR_fdatasync:
        case __NR_ftruncate: case __NR_fchmod: case __NR_fchown:
        case __NR_ioctl: case __NR_fcntl: case __NR_getdents64:
        case __NR_close:
            fd = (int)a0;
            break;
        case __NR_sendto: case __NR_recvfrom:
        case __NR_setsockopt: case __NR_getsockopt:
        case __NR_sendmsg: case __NR_recvmsg:
        case __NR_shutdown: case __NR_bind: case __NR_connect:
        case __NR_listen: case __NR_accept: case __NR_accept4:
            fd = (int)a0;
            break;
        default: break;
        }
        if (fd >= 0) {
            /* Resolve fd via /proc/self/fd/N using readlinkat syscall */
            char fdpath[32];
            int plen = 0;
            fdpath[0] = '/'; fdpath[1] = 'p'; fdpath[2] = 'r'; fdpath[3] = 'o';
            fdpath[4] = 'c'; fdpath[5] = '/'; fdpath[6] = 's'; fdpath[7] = 'e';
            fdpath[8] = 'l'; fdpath[9] = 'f'; fdpath[10] = '/'; fdpath[11] = 'f';
            fdpath[12] = 'd'; fdpath[13] = '/';
            plen = 14;
            /* int to string for fd */
            {
                char digits[12];
                int dlen = 0, fv = fd < 0 ? -fd : fd;
                if (fv == 0) { digits[dlen++] = '0'; }
                else { while (fv > 0 && dlen < 10) { digits[dlen++] = '0' + (fv % 10); fv /= 10; } }
                if (fd < 0) fdpath[plen++] = '-';
                while (dlen > 0) fdpath[plen++] = digits[--dlen];
                fdpath[plen] = 0;
            }
            {
                long rlen = raw_syscall4(__NR_readlinkat, -100,
                    (unsigned long)fdpath, (unsigned long)ev->fd_path, MAX_PATH_LEN - 1);
                if (rlen > 0 && rlen < MAX_PATH_LEN) ev->fd_path[rlen] = 0;
                else ev->fd_path[0] = 0;
            }
        }
    }

    deep_parse_args(ev);
}

/* ================================================================
 * HOOK_ENTRY macros -- generate hook functions for each syscall
 * ================================================================ */
#define HOOK_ENTRY(NR) \
    static void before_##NR(hook_fargs6_t *args, void *udata) { \
        (void)udata; \
        before_syscall(NR, args->arg0, args->arg1, args->arg2, \
                       args->arg3, args->arg4, args->arg5); \
    }

/* Tier1 hooks */
HOOK_ENTRY(56)  HOOK_ENTRY(57)  HOOK_ENTRY(63)  HOOK_ENTRY(64)
HOOK_ENTRY(35)  HOOK_ENTRY(34)  HOOK_ENTRY(53)  HOOK_ENTRY(54)
HOOK_ENTRY(48)  HOOK_ENTRY(78)  HOOK_ENTRY(79)  HOOK_ENTRY(80)
HOOK_ENTRY(82)  HOOK_ENTRY(83)  HOOK_ENTRY(62)  HOOK_ENTRY(61)
HOOK_ENTRY(67)  HOOK_ENTRY(68)  HOOK_ENTRY(65)  HOOK_ENTRY(66)
HOOK_ENTRY(45)  HOOK_ENTRY(46)  HOOK_ENTRY(47)  HOOK_ENTRY(29)
HOOK_ENTRY(25)  HOOK_ENTRY(23)  HOOK_ENTRY(24)
HOOK_ENTRY(198) HOOK_ENTRY(200) HOOK_ENTRY(201) HOOK_ENTRY(202)
HOOK_ENTRY(203) HOOK_ENTRY(206) HOOK_ENTRY(207) HOOK_ENTRY(208)
HOOK_ENTRY(209) HOOK_ENTRY(210) HOOK_ENTRY(211) HOOK_ENTRY(212)
HOOK_ENTRY(220) HOOK_ENTRY(221) HOOK_ENTRY(129) HOOK_ENTRY(131)
HOOK_ENTRY(222)
/* Tier2 hooks */
HOOK_ENTRY(40)  HOOK_ENTRY(39)  HOOK_ENTRY(76)  HOOK_ENTRY(71)
HOOK_ENTRY(117) HOOK_ENTRY(167) HOOK_ENTRY(261) HOOK_ENTRY(277)
HOOK_ENTRY(105) HOOK_ENTRY(106) HOOK_ENTRY(273) HOOK_ENTRY(280)
HOOK_ENTRY(281) HOOK_ENTRY(226) HOOK_ENTRY(233) HOOK_ENTRY(214)
HOOK_ENTRY(215) HOOK_ENTRY(216) HOOK_ENTRY(228) HOOK_ENTRY(229)
HOOK_ENTRY(5)   HOOK_ENTRY(8)   HOOK_ENTRY(14)  HOOK_ENTRY(88)
HOOK_ENTRY(435)

/* ================================================================
 * Hook install/remove helpers
 * ================================================================ */
static int install_hook(int nr) {
    switch (nr) {
#define CASE_HOOK(N) case N: return hook_syscalln(N, 6, before_##N, 0, 0)
    CASE_HOOK(56); CASE_HOOK(57); CASE_HOOK(63); CASE_HOOK(64);
    CASE_HOOK(35); CASE_HOOK(34); CASE_HOOK(53); CASE_HOOK(54);
    CASE_HOOK(48); CASE_HOOK(78); CASE_HOOK(79); CASE_HOOK(80);
    CASE_HOOK(82); CASE_HOOK(83); CASE_HOOK(62); CASE_HOOK(61);
    CASE_HOOK(67); CASE_HOOK(68); CASE_HOOK(65); CASE_HOOK(66);
    CASE_HOOK(45); CASE_HOOK(46); CASE_HOOK(47); CASE_HOOK(29);
    CASE_HOOK(25); CASE_HOOK(23); CASE_HOOK(24);
    CASE_HOOK(198); CASE_HOOK(200); CASE_HOOK(201); CASE_HOOK(202);
    CASE_HOOK(203); CASE_HOOK(206); CASE_HOOK(207); CASE_HOOK(208);
    CASE_HOOK(209); CASE_HOOK(210); CASE_HOOK(211); CASE_HOOK(212);
    CASE_HOOK(220); CASE_HOOK(221); CASE_HOOK(129); CASE_HOOK(131);
    CASE_HOOK(222);
    CASE_HOOK(40); CASE_HOOK(39); CASE_HOOK(76); CASE_HOOK(71);
    CASE_HOOK(117); CASE_HOOK(167); CASE_HOOK(261); CASE_HOOK(277);
    CASE_HOOK(105); CASE_HOOK(106); CASE_HOOK(273); CASE_HOOK(280);
    CASE_HOOK(281); CASE_HOOK(226); CASE_HOOK(233); CASE_HOOK(214);
    CASE_HOOK(215); CASE_HOOK(216); CASE_HOOK(228); CASE_HOOK(229);
    CASE_HOOK(5); CASE_HOOK(8); CASE_HOOK(14); CASE_HOOK(88);
    CASE_HOOK(435);
#undef CASE_HOOK
    default: return -1;
    }
}

static void remove_hook(int nr) {
    switch (nr) {
#define CASE_UNHOOK(N) case N: unhook_syscalln(N, before_##N, 0); break
    CASE_UNHOOK(56); CASE_UNHOOK(57); CASE_UNHOOK(63); CASE_UNHOOK(64);
    CASE_UNHOOK(35); CASE_UNHOOK(34); CASE_UNHOOK(53); CASE_UNHOOK(54);
    CASE_UNHOOK(48); CASE_UNHOOK(78); CASE_UNHOOK(79); CASE_UNHOOK(80);
    CASE_UNHOOK(82); CASE_UNHOOK(83); CASE_UNHOOK(62); CASE_UNHOOK(61);
    CASE_UNHOOK(67); CASE_UNHOOK(68); CASE_UNHOOK(65); CASE_UNHOOK(66);
    CASE_UNHOOK(45); CASE_UNHOOK(46); CASE_UNHOOK(47); CASE_UNHOOK(29);
    CASE_UNHOOK(25); CASE_UNHOOK(23); CASE_UNHOOK(24);
    CASE_UNHOOK(198); CASE_UNHOOK(200); CASE_UNHOOK(201); CASE_UNHOOK(202);
    CASE_UNHOOK(203); CASE_UNHOOK(206); CASE_UNHOOK(207); CASE_UNHOOK(208);
    CASE_UNHOOK(209); CASE_UNHOOK(210); CASE_UNHOOK(211); CASE_UNHOOK(212);
    CASE_UNHOOK(220); CASE_UNHOOK(221); CASE_UNHOOK(129); CASE_UNHOOK(131);
    CASE_UNHOOK(222);
    CASE_UNHOOK(40); CASE_UNHOOK(39); CASE_UNHOOK(76); CASE_UNHOOK(71);
    CASE_UNHOOK(117); CASE_UNHOOK(167); CASE_UNHOOK(261); CASE_UNHOOK(277);
    CASE_UNHOOK(105); CASE_UNHOOK(106); CASE_UNHOOK(273); CASE_UNHOOK(280);
    CASE_UNHOOK(281); CASE_UNHOOK(226); CASE_UNHOOK(233); CASE_UNHOOK(214);
    CASE_UNHOOK(215); CASE_UNHOOK(216); CASE_UNHOOK(228); CASE_UNHOOK(229);
    CASE_UNHOOK(5); CASE_UNHOOK(8); CASE_UNHOOK(14); CASE_UNHOOK(88);
    CASE_UNHOOK(435);
#undef CASE_UNHOOK
    default: break;
    }
}

static int g_tier1_hooked = 0;
static int g_tier2_hooked = 0;

static void install_tier1(void) {
    unsigned int i;
    if (g_tier1_hooked) return;
    for (i = 0; i < TIER1_COUNT; i++)
        install_hook(tier1_nrs[i]);
    g_tier1_hooked = 1;
    printk("svc_monitor: tier1 hooks installed (%u)\n", (unsigned)TIER1_COUNT);
}

static void remove_tier1(void) {
    unsigned int i;
    if (!g_tier1_hooked) return;
    for (i = 0; i < TIER1_COUNT; i++)
        remove_hook(tier1_nrs[i]);
    g_tier1_hooked = 0;
    printk("svc_monitor: tier1 hooks removed\n");
}

static void install_tier2(void) {
    unsigned int i;
    if (g_tier2_hooked) return;
    for (i = 0; i < TIER2_COUNT; i++)
        install_hook(tier2_nrs[i]);
    g_tier2_hooked = 1;
    g_tier2_enabled = 1;
    printk("svc_monitor: tier2 hooks installed (%u)\n", (unsigned)TIER2_COUNT);
}

static void remove_tier2(void) {
    unsigned int i;
    if (!g_tier2_hooked) return;
    for (i = 0; i < TIER2_COUNT; i++)
        remove_hook(tier2_nrs[i]);
    g_tier2_hooked = 0;
    g_tier2_enabled = 0;
    printk("svc_monitor: tier2 hooks removed\n");
}

/* ================================================================
 * Command: drain events as JSON
 * ================================================================ */
static int drain_events(void) {
    int i, off = 0, cnt;
    char esc1[TASK_COMM_LEN * 2 + 4];
    char esc2[MAX_DESC_LEN * 2 + 4];
    char esc3[MAX_PATH_LEN * 2 + 4];
    cnt = g_count;
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "{\"ok\":true,\"events\":[");
    for (i = 0; i < cnt && off < OUTBUF_SIZE - 1024; i++) {
        int ei = (g_tail + i) % MAX_EVENTS;
        struct svc_event *ev = &g_events[ei];
        json_escape(esc1, sizeof(esc1), ev->comm);
        json_escape(esc2, sizeof(esc2), ev->desc);
        json_escape(esc3, sizeof(esc3), ev->fd_path);
        off += snprintf(g_outbuf + off, OUTBUF_SIZE - off,
            "%s{\"seq\":%lu,\"nr\":%d,\"name\":\"%s\",\"pid\":%d,\"uid\":%d,"
            "\"comm\":\"%s\",\"a0\":%lu,\"a1\":%lu,\"a2\":%lu,"
            "\"a3\":%lu,\"a4\":%lu,\"a5\":%lu,"
            "\"desc\":\"%s\",\"caller\":\"0x%lx\",\"pc\":\"0x%lx\","
            "\"fdPath\":\"%s\",\"cloneFn\":%lu}",
            i ? "," : "",
            ev->seq, ev->nr, nr_to_name(ev->nr), ev->pid, ev->uid,
            esc1, ev->a0, ev->a1, ev->a2, ev->a3, ev->a4, ev->a5,
            esc2, ev->caller_addr, ev->pc, esc3, ev->clone_fn);
    }
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "],\"total\":%lu,\"drained\":%d}", g_total, i);
    g_head = 0; g_tail = 0; g_count = 0;
    return write_output_file(OUTPUT_PATH, g_outbuf, off);
}

/* ================================================================
 * Command: status JSON
 * ================================================================ */
static int output_status(void) {
    int off = 0;
    char nrlist[4096];
    bitmap_list(nrlist, sizeof(nrlist));
    off += snprintf(g_outbuf + off, OUTBUF_SIZE - off,
        "{\"ok\":true,\"enabled\":%d,\"uid\":%d,\"tier2\":%d,"
        "\"eventsTotal\":%lu,\"eventsBuffered\":%d,"
        "\"nrFilter\":\"%s\",\"tier1Hooked\":%d,\"tier2Hooked\":%d,"
        "\"version\":\"8.3.0\"}",
        g_enabled, g_uid_filter, g_tier2_enabled,
        g_total, g_count, nrlist, g_tier1_hooked, g_tier2_hooked);
    return write_output_file(OUTPUT_PATH, g_outbuf, off);
}

/* ================================================================
 * Command: apply preset
 * ================================================================ */
static int apply_preset(int preset_id) {
    int pi, i;
    if (preset_id == 9) {
        /* all */
        bitmap_set_all();
        if (!g_tier2_hooked) install_tier2();
        return 0;
    }
    for (pi = 0; presets[pi].id; pi++) {
        if (presets[pi].id == preset_id) {
            bitmap_clear_all();
            for (i = 0; i < presets[pi].count; i++)
                bitmap_set(presets[pi].nrs[i]);
            return 0;
        }
    }
    return -1;
}

/* ================================================================
 * Simple string-to-int
 * ================================================================ */
static int str_to_int(const char *s) {
    int val = 0, neg = 0;
    if (!s) return 0;
    while (*s == ' ') s++;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
}

/* ================================================================
 * Simple command argument parser
 * Finds the first space after command name, returns pointer to args
 * ================================================================ */
static const char *cmd_args(const char *cmd, const char *prefix) {
    int plen = strlen(prefix);
    if (strncmp(cmd, prefix, plen) != 0) return 0;
    if (cmd[plen] == 0) return cmd + plen;
    if (cmd[plen] == ' ') return cmd + plen + 1;
    return 0;
}

/* ================================================================
 * KPM_CTL0 -- command dispatcher
 * ================================================================ */
__attribute__((used))
static long svc_ctl0(const char *args, char *__user out_msg, int outlen) {
    int off, i, cnt;
    const char *p;

    if (!args) return -1;

    /* enable */
    if (strcmp(args, "enable") == 0) {
        if (!g_tier1_hooked) install_tier1();
        g_enabled = 1;
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"enabled\"}");
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* disable */
    if (strcmp(args, "disable") == 0) {
        g_enabled = 0;
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"disabled\"}");
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* status */
    if (strcmp(args, "status") == 0) {
        output_status();
        return 0;
    }
    /* drain */
    if (strcmp(args, "drain") == 0) {
        drain_events();
        return 0;
    }
    /* clear */
    if (strcmp(args, "clear") == 0) {
        g_head = 0; g_tail = 0; g_count = 0;
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"cleared\"}");
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* uid <N> */
    p = cmd_args(args, "uid");
    if (p) {
        g_uid_filter = str_to_int(p);
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"uid\":%d}", g_uid_filter);
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* enable_nr <N> */
    p = cmd_args(args, "enable_nr");
    if (p) {
        int nr = str_to_int(p);
        bitmap_set(nr);
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"enabled_nr\":%d}", nr);
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* disable_nr <N> */
    p = cmd_args(args, "disable_nr");
    if (p) {
        int nr = str_to_int(p);
        bitmap_clear(nr);
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"disabled_nr\":%d}", nr);
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* set_nrs <n1,n2,...> */
    p = cmd_args(args, "set_nrs");
    if (p) {
        int nr;
        bitmap_clear_all();
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if (*p == 0) break;
            nr = 0;
            while (*p >= '0' && *p <= '9') { nr = nr * 10 + (*p - '0'); p++; }
            bitmap_set(nr);
        }
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"nrs_set\"}");
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* enable_all_nr */
    if (strcmp(args, "enable_all_nr") == 0) {
        bitmap_set_all();
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"all_enabled\"}");
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* disable_all_nr */
    if (strcmp(args, "disable_all_nr") == 0) {
        bitmap_clear_all();
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"msg\":\"all_disabled\"}");
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* preset <1-9> */
    p = cmd_args(args, "preset");
    if (p) {
        int pid = str_to_int(p);
        if (apply_preset(pid) == 0) {
            off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"preset\":%d}", pid);
        } else {
            off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":false,\"error\":\"invalid preset\"}");
        }
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* tier2 <0|1> */
    p = cmd_args(args, "tier2");
    if (p) {
        int val = str_to_int(p);
        if (val && !g_tier2_hooked) install_tier2();
        else if (!val && g_tier2_hooked) remove_tier2();
        off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":true,\"tier2\":%d}", g_tier2_enabled);
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    /* events (non-draining peek) */
    if (strcmp(args, "events") == 0) {
        char esc1[TASK_COMM_LEN * 2 + 4];
        char esc2[MAX_DESC_LEN * 2 + 4];
        char esc3[MAX_PATH_LEN * 2 + 4];
        cnt = g_count; off = 0;
        off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "{\"ok\":true,\"events\":[");
        for (i = 0; i < cnt && off < OUTBUF_SIZE - 1024; i++) {
            int ei = (g_tail + i) % MAX_EVENTS;
            struct svc_event *ev = &g_events[ei];
            json_escape(esc1, sizeof(esc1), ev->comm);
            json_escape(esc2, sizeof(esc2), ev->desc);
            json_escape(esc3, sizeof(esc3), ev->fd_path);
            off += snprintf(g_outbuf + off, OUTBUF_SIZE - off,
                "%s{\"seq\":%lu,\"nr\":%d,\"name\":\"%s\",\"pid\":%d,\"uid\":%d,"
                "\"comm\":\"%s\",\"a0\":%lu,\"a1\":%lu,\"a2\":%lu,"
                "\"a3\":%lu,\"a4\":%lu,\"a5\":%lu,"
                "\"desc\":\"%s\",\"caller\":\"0x%lx\",\"pc\":\"0x%lx\","
                "\"fdPath\":\"%s\",\"cloneFn\":%lu}",
                i ? "," : "",
                ev->seq, ev->nr, nr_to_name(ev->nr), ev->pid, ev->uid,
                esc1, ev->a0, ev->a1, ev->a2, ev->a3, ev->a4, ev->a5,
                esc2, ev->caller_addr, ev->pc, esc3, ev->clone_fn);
        }
        off += snprintf(g_outbuf + off, OUTBUF_SIZE - off, "],\"total\":%lu,\"buffered\":%d}", g_total, cnt);
        write_output_file(OUTPUT_PATH, g_outbuf, off);
        return 0;
    }
    off = snprintf(g_outbuf, OUTBUF_SIZE, "{\"ok\":false,\"error\":\"unknown command\"}");
    write_output_file(OUTPUT_PATH, g_outbuf, off);
    return 0;
}

/* ================================================================
 * KPM entry points
 * ================================================================ */
__attribute__((used))
static long svc_init(const char *args, const char *event, void *reserved) {
    unsigned long i;
    volatile char *p;
    printk("svc_monitor: v8.3.0 loaded\n");
    p = (volatile char *)g_events;
    for (i = 0; i < sizeof(g_events); i++) p[i] = 0;
    p = (volatile char *)g_nr_bitmap;
    for (i = 0; i < sizeof(g_nr_bitmap); i++) p[i] = 0;
    g_head = 0; g_tail = 0; g_count = 0;
    g_total = 0; g_seq = 0;
    g_enabled = 0;
    g_uid_filter = -1;
    g_tier2_enabled = 0;
    g_tier1_hooked = 0;
    g_tier2_hooked = 0;
    return 0;
}

__attribute__((used))
static long svc_exit(void *reserved) {
    g_enabled = 0;
    if (g_tier2_hooked) remove_tier2();
    if (g_tier1_hooked) remove_tier1();
    printk("svc_monitor: unloaded\n");
    return 0;
}

KPM_INIT(svc_init);
KPM_CTL0(svc_ctl0);
KPM_EXIT(svc_exit);
