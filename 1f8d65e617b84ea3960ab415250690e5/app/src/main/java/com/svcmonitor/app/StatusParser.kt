package com.svcmonitor.app

import org.json.JSONObject
import org.json.JSONArray

/* ============================================================
 * Data classes
 * ============================================================ */

data class SvcEvent(
    val seq: Long,
    val nr: Int,
    val name: String,
    val pid: Int,
    val uid: Int,
    val comm: String,
    val a0: Long, val a1: Long, val a2: Long,
    val a3: Long, val a4: Long, val a5: Long,
    val desc: String,
    val caller: String,       // SO+offset or [anon] or hex addr
    val callerAddr: String,   // raw hex address
    val pc: String,
    val fdPath: String,
    val cloneFn: Long
)

data class ModuleStatus(
    val ok: Boolean,
    val enabled: Boolean,
    val uid: Int,
    val tier2: Boolean,
    val eventsTotal: Long,
    val eventsBuffered: Int,
    val nrFilter: String,
    val tier1Hooked: Boolean,
    val tier2Hooked: Boolean,
    val version: String
)

data class DrainResult(val ok: Boolean, val events: List<SvcEvent>, val total: Long, val drained: Int)
data class SimpleResult(val ok: Boolean, val msg: String)

data class Preset(val id: Int, val name: String, val description: String) {
    companion object {
        val ALL_PRESETS = listOf(
            Preset(1, "file_io", "File I/O: open, read, write, close..."),
            Preset(2, "fs_ops", "FS Ops: unlink, mkdir, chmod, rename..."),
            Preset(3, "network", "Network: socket, connect, bind, send..."),
            Preset(4, "process", "Process: clone, execve, exit, wait..."),
            Preset(5, "signal", "Signal: kill, tgkill, sigaction..."),
            Preset(6, "memory", "Memory: mmap, mprotect, munmap, brk..."),
            Preset(7, "ipc", "IPC: futex, robust_list..."),
            Preset(8, "security", "Security: seccomp, bpf, ptrace..."),
            Preset(9, "all", "All syscalls (tier1 + tier2)")
        )
    }
}

/* ============================================================
 * Syscall NR -> name mapping
 * ============================================================ */
object SyscallInfo {
    val NR_NAMES = mapOf(
        0 to "io_setup",
        2 to "io_submit",
        3 to "io_cancel",
        5 to "setxattr",
        8 to "getxattr",
        11 to "listxattr",
        14 to "removexattr",
        19 to "eventfd2",
        20 to "epoll_create1",
        21 to "epoll_ctl",
        22 to "epoll_pwait",
        23 to "dup",
        24 to "dup3",
        25 to "fcntl",
        26 to "inotify_init1",
        27 to "inotify_add_watch",
        28 to "inotify_rm_watch",
        29 to "ioctl",
        33 to "mknodat",
        34 to "mkdirat",
        35 to "unlinkat",
        36 to "symlinkat",
        37 to "linkat",
        38 to "renameat",
        39 to "umount2",
        40 to "mount",
        41 to "pivot_root",
        43 to "statfs",
        44 to "fstatfs",
        46 to "ftruncate",
        47 to "fallocate",
        48 to "faccessat",
        49 to "chdir",
        50 to "fchdir",
        51 to "chroot",
        52 to "fchmod",
        53 to "fchmodat",
        54 to "fchownat",
        55 to "fchown",
        56 to "openat",
        57 to "close",
        59 to "pipe2",
        62 to "lseek",
        63 to "read",
        64 to "write",
        65 to "readv",
        66 to "writev",
        67 to "pread64",
        68 to "pwrite64",
        71 to "sendfile",
        72 to "pselect6",
        73 to "ppoll",
        74 to "signalfd4",
        76 to "splice",
        78 to "readlinkat",
        79 to "fstatat",
        80 to "fstat",
        82 to "fsync",
        83 to "fdatasync",
        85 to "timerfd_create",
        86 to "timerfd_settime",
        90 to "capget",
        91 to "capset",
        92 to "personality",
        93 to "exit",
        94 to "exit_group",
        95 to "waitid",
        97 to "unshare",
        98 to "futex",
        99 to "set_robust_list",
        117 to "ptrace",
        129 to "kill",
        130 to "tkill",
        131 to "tgkill",
        134 to "rt_sigaction",
        135 to "rt_sigprocmask",
        139 to "rt_sigreturn",
        144 to "setgid",
        146 to "setuid",
        147 to "setresuid",
        149 to "setresgid",
        167 to "prctl",
        172 to "getpid",
        173 to "getppid",
        174 to "getuid",
        175 to "geteuid",
        176 to "getgid",
        177 to "getegid",
        178 to "gettid",
        198 to "socket",
        199 to "socketpair",
        200 to "bind",
        201 to "listen",
        203 to "connect",
        204 to "getsockname",
        205 to "getpeername",
        206 to "sendto",
        207 to "recvfrom",
        208 to "setsockopt",
        209 to "getsockopt",
        210 to "shutdown",
        211 to "sendmsg",
        212 to "recvmsg",
        214 to "brk",
        215 to "munmap",
        216 to "mremap",
        220 to "clone",
        221 to "execve",
        222 to "mmap",
        226 to "mprotect",
        227 to "msync",
        228 to "mlock",
        229 to "munlock",
        233 to "madvise",
        241 to "perf_event_open",
        242 to "accept4",
        260 to "wait4",
        268 to "setns",
        276 to "renameat2",
        277 to "seccomp",
        278 to "getrandom",
        279 to "memfd_create",
        280 to "bpf",
        282 to "userfaultfd",
        285 to "copy_file_range",
        424 to "pidfd_send_signal",
        425 to "io_uring_setup",
        426 to "io_uring_enter",
        434 to "pidfd_open",
        435 to "clone3",
    )

    val CATEGORIES = mapOf(
        "File I/O" to listOf(56, 57, 63, 64, 65, 66, 67, 68, 62, 76, 82, 83, 71),
        "Filesystem" to listOf(35, 34, 48, 53, 54, 78, 79, 80, 38, 276, 36, 37, 33),
        "Network" to listOf(198, 199, 200, 201, 203, 206, 207, 208, 209, 210, 211, 212, 242),
        "Process" to listOf(220, 221, 435, 93, 94, 260, 95),
        "Memory" to listOf(222, 226, 215, 216, 233, 227, 228, 229, 214),
        "Security" to listOf(277, 280, 117, 167, 146, 147, 129, 130, 131)
    )
}

/* ============================================================
 * JSON parsers
 * ============================================================ */
object StatusParser {

    fun parseEvent(j: JSONObject): SvcEvent = SvcEvent(
        seq = j.optLong("seq", 0),
        nr = j.optInt("nr", -1),
        name = j.optString("name", "?"),
        pid = j.optInt("pid", 0),
        uid = j.optInt("uid", 0),
        comm = j.optString("comm", ""),
        a0 = j.optLong("a0", 0), a1 = j.optLong("a1", 0), a2 = j.optLong("a2", 0),
        a3 = j.optLong("a3", 0), a4 = j.optLong("a4", 0), a5 = j.optLong("a5", 0),
        desc = j.optString("desc", ""),
        caller = j.optString("caller", ""),
        callerAddr = j.optString("callerAddr", ""),
        pc = j.optString("pc", ""),
        fdPath = j.optString("fdPath", ""),
        cloneFn = j.optLong("cloneFn", 0)
    )

    fun parseStatus(json: String): ModuleStatus? {
        return try {
            val j = JSONObject(json)
            ModuleStatus(
                ok = j.optBoolean("ok", false),
                enabled = j.optBoolean("enabled", false) || j.optInt("enabled", 0) == 1,
                uid = j.optInt("uid", 0),
                tier2 = j.optBoolean("tier2", false) || j.optInt("tier2", 0) == 1,
                eventsTotal = j.optLong("eventsTotal", 0),
                eventsBuffered = j.optInt("eventsBuffered", 0),
                nrFilter = j.optString("nrFilter", ""),
                tier1Hooked = j.optBoolean("tier1Hooked", false) || j.optInt("tier1Hooked", 0) == 1,
                tier2Hooked = j.optBoolean("tier2Hooked", false) || j.optInt("tier2Hooked", 0) == 1,
                version = j.optString("version", "?")
            )
        } catch (e: Exception) { null }
    }

    fun parseDrain(json: String): DrainResult? {
        return try {
            val j = JSONObject(json)
            val arr = j.optJSONArray("events") ?: JSONArray()
            val list = (0 until arr.length()).map { parseEvent(arr.getJSONObject(it)) }
            DrainResult(
                ok = j.optBoolean("ok", false),
                events = list,
                total = j.optLong("total", 0),
                drained = j.optInt("drained", 0)
            )
        } catch (e: Exception) { null }
    }

    fun parseEvents(json: String): List<SvcEvent> {
        return try {
            val j = JSONObject(json)
            val arr = j.optJSONArray("events") ?: JSONArray()
            (0 until arr.length()).map { parseEvent(arr.getJSONObject(it)) }
        } catch (e: Exception) { emptyList() }
    }

    fun parseSimple(json: String): SimpleResult {
        return try {
            val j = JSONObject(json)
            SimpleResult(j.optBoolean("ok", false), j.optString("msg", json))
        } catch (e: Exception) {
            SimpleResult(false, json.ifEmpty { "No response" })
        }
    }
}
