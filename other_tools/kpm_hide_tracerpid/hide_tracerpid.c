#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/current.h>

KPM_NAME("kpm-hide-tracerpid");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("SVC_Call");
KPM_DESCRIPTION("Hide /proc/*/status TracerPid by patching read buffer");

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct pid_namespace;
static pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

static enum hook_type g_hook_type = NONE;
static int g_hook_installed = 0;

#define TRACKED_MAX 128
struct tracked_item
{
    pid_t tgid;
    int fd;
};

static struct tracked_item g_tracked[TRACKED_MAX];

static int is_proc_status_path(const char *path)
{
    if (!path) return 0;
    if (!strcmp(path, "/proc/self/status")) return 1;
    if (path[0] != '/') return 0;
    if (strncmp(path, "/proc/", 6)) return 0;
    size_t len = strlen(path);
    if (len < 7) return 0;
    if (strcmp(path + len - 7, "/status")) return 0;
    return 1;
}

static pid_t current_tgid(void)
{
    if (!__task_pid_nr_ns) return -1;
    return __task_pid_nr_ns(current, PIDTYPE_TGID, 0);
}

static void track_fd(pid_t tgid, int fd)
{
    if (tgid <= 0 || fd < 0) return;

    int empty = -1;
    for (int i = 0; i < TRACKED_MAX; i++) {
        if (g_tracked[i].tgid == tgid) {
            g_tracked[i].fd = fd;
            return;
        }
        if (empty < 0 && g_tracked[i].tgid == 0) empty = i;
    }
    if (empty >= 0) {
        g_tracked[empty].tgid = tgid;
        g_tracked[empty].fd = fd;
    } else {
        g_tracked[0].tgid = tgid;
        g_tracked[0].fd = fd;
    }
}

static void untrack_fd(pid_t tgid, int fd)
{
    if (tgid <= 0 || fd < 0) return;

    for (int i = 0; i < TRACKED_MAX; i++) {
        if (g_tracked[i].tgid == tgid && g_tracked[i].fd == fd) {
            g_tracked[i].tgid = 0;
            g_tracked[i].fd = 0;
            break;
        }
    }
}

static int is_tracked_fd(pid_t tgid, int fd)
{
    if (tgid <= 0 || fd < 0) return 0;

    int hit = 0;
    for (int i = 0; i < TRACKED_MAX; i++) {
        if (g_tracked[i].tgid == tgid && g_tracked[i].fd == fd) {
            hit = 1;
            break;
        }
    }
    return hit;
}

static void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    char path[256];
    path[0] = 0;
    compat_strncpy_from_user(path, filename, sizeof(path));
    args->local.data0 = is_proc_status_path(path) ? 1 : 0;
}

static void after_openat(hook_fargs4_t *args, void *udata)
{
    if (!args->local.data0) return;
    int fd = (int)args->ret;
    pid_t tgid = current_tgid();
    track_fd(tgid, fd);
}

static void after_close(hook_fargs1_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    pid_t tgid = current_tgid();
    untrack_fd(tgid, fd);
}

static void patch_tracerpid_field(char __user *ubuf, int len)
{
    if (!ubuf || len <= 0) return;
    int cap = len;
    if (cap > 4096) cap = 4096;

    char buf[4097];
    buf[0] = 0;
    compat_strncpy_from_user(buf, ubuf, cap);

    const char *key = "TracerPid:";
    char *p = strstr(buf, key);
    if (!p) return;

    int idx = (int)(p - buf) + (int)strlen(key);
    while (idx < cap && (buf[idx] == ' ' || buf[idx] == '\t')) idx++;

    int digits = 0;
    while (idx + digits < cap) {
        char c = buf[idx + digits];
        if (c < '0' || c > '9') break;
        digits++;
    }
    if (digits <= 0) return;

    char zeros[32];
    if (digits > (int)sizeof(zeros)) digits = (int)sizeof(zeros);
    for (int i = 0; i < digits; i++) zeros[i] = '0';
    compat_copy_to_user(ubuf + idx, zeros, digits);
}

static void after_read(hook_fargs3_t *args, void *udata)
{
    long rc = (long)args->ret;
    if (rc <= 0) return;

    int fd = (int)syscall_argn(args, 0);
    pid_t tgid = current_tgid();
    if (!is_tracked_fd(tgid, fd)) return;

    char __user *buf = (char __user *)syscall_argn(args, 1);
    patch_tracerpid_field(buf, (int)rc);
}

static void after_pread64(hook_fargs4_t *args, void *udata)
{
    long rc = (long)args->ret;
    if (rc <= 0) return;

    int fd = (int)syscall_argn(args, 0);
    pid_t tgid = current_tgid();
    if (!is_tracked_fd(tgid, fd)) return;

    char __user *buf = (char __user *)syscall_argn(args, 1);
    patch_tracerpid_field(buf, (int)rc);
}

static hook_err_t install_hooks(enum hook_type ht)
{
    hook_err_t err = HOOK_NO_ERR;
    if (ht == INLINE_CHAIN) {
        err = inline_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
        if (err) return err;
        err = inline_hook_syscalln(__NR_read, 3, 0, after_read, 0);
        if (err) goto fail_inline;
        err = inline_hook_syscalln(__NR_close, 1, 0, after_close, 0);
        if (err) goto fail_inline;
        err = inline_hook_syscalln(__NR_pread64, 4, 0, after_pread64, 0);
        if (err) goto fail_inline;
        return HOOK_NO_ERR;
    }

    err = fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    if (err) return err;
    err = fp_hook_syscalln(__NR_read, 3, 0, after_read, 0);
    if (err) goto fail_fp;
    err = fp_hook_syscalln(__NR_close, 1, 0, after_close, 0);
    if (err) goto fail_fp;
    err = fp_hook_syscalln(__NR_pread64, 4, 0, after_pread64, 0);
    if (err) goto fail_fp;
    return HOOK_NO_ERR;

fail_inline:
    inline_unhook_syscalln(__NR_pread64, 0, after_pread64);
    inline_unhook_syscalln(__NR_close, 0, after_close);
    inline_unhook_syscalln(__NR_read, 0, after_read);
    inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
    return err;

fail_fp:
    fp_unhook_syscalln(__NR_pread64, 0, after_pread64);
    fp_unhook_syscalln(__NR_close, 0, after_close);
    fp_unhook_syscalln(__NR_read, 0, after_read);
    fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    return err;
}

static void uninstall_hooks(enum hook_type ht)
{
    if (ht == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
        inline_unhook_syscalln(__NR_read, 0, after_read);
        inline_unhook_syscalln(__NR_close, 0, after_close);
        inline_unhook_syscalln(__NR_pread64, 0, after_pread64);
        return;
    }
    if (ht == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
        fp_unhook_syscalln(__NR_read, 0, after_read);
        fp_unhook_syscalln(__NR_close, 0, after_close);
        fp_unhook_syscalln(__NR_pread64, 0, after_pread64);
        return;
    }
}

static long hide_tracerpid_init(const char *args, const char *event, void *reserved)
{
    for (int i = 0; i < TRACKED_MAX; i++) {
        g_tracked[i].tgid = 0;
        g_tracked[i].fd = 0;
    }

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    if (!__task_pid_nr_ns) {
        pr_err("kpm-hide-tracerpid: resolve __task_pid_nr_ns failed\n");
        return 0;
    }

    enum hook_type ht = FUNCTION_POINTER_CHAIN;
    if (args && !strcmp(args, "inline")) ht = INLINE_CHAIN;
    g_hook_type = ht;

    hook_err_t err = install_hooks(ht);
    if (err) {
        pr_err("kpm-hide-tracerpid: install hooks failed: %d\n", err);
        return 0;
    }

    g_hook_installed = 1;
    pr_info("kpm-hide-tracerpid: installed, hook_type=%d\n", ht);
    return 0;
}

static long hide_tracerpid_ctl0(const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!ctl_args) return 0;

    if (!strcmp(ctl_args, "off")) {
        if (g_hook_installed) {
            uninstall_hooks(g_hook_type);
            g_hook_installed = 0;
        }
        return 0;
    }

    if (!strcmp(ctl_args, "on")) {
        if (!g_hook_installed) {
            hook_err_t err = install_hooks(g_hook_type);
            if (!err) g_hook_installed = 1;
        }
        return 0;
    }

    return 0;
}

static long hide_tracerpid_exit(void *reserved)
{
    if (g_hook_installed) uninstall_hooks(g_hook_type);
    g_hook_installed = 0;
    pr_info("kpm-hide-tracerpid: exit\n");
    return 0;
}

KPM_INIT(hide_tracerpid_init);
KPM_CTL0(hide_tracerpid_ctl0);
KPM_EXIT(hide_tracerpid_exit);
