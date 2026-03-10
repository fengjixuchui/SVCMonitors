package com.svcmonitor.app

import org.json.JSONObject
import org.json.JSONArray

/**
 * StatusParser -- parses JSON responses from the kernel module.
 * SVCMonitor v8.3
 */

data class SvcEvent(
    val seq: Long = 0,
    val nr: Int = 0,
    val name: String = "",
    val pid: Int = 0,
    val uid: Int = 0,
    val comm: String = "",
    val a0: Long = 0, val a1: Long = 0, val a2: Long = 0,
    val a3: Long = 0, val a4: Long = 0, val a5: Long = 0,
    val desc: String = "",
    val caller: String = "",
    val pc: String = "",
    val fdPath: String = "",
    val cloneFn: Long = 0
)

data class ModuleStatus(
    val ok: Boolean = false,
    val enabled: Boolean = false,
    val uid: Int = -1,
    val tier2: Boolean = false,
    val eventsTotal: Long = 0,
    val eventsBuffered: Int = 0,
    val nrFilter: String = "",
    val tier1Hooked: Boolean = false,
    val tier2Hooked: Boolean = false,
    val version: String = ""
)

data class DrainResult(
    val ok: Boolean = false,
    val events: List<SvcEvent> = emptyList(),
    val total: Long = 0,
    val drained: Int = 0,
    val buffered: Int = 0
)

data class SimpleResult(
    val ok: Boolean = false,
    val msg: String = "",
    val error: String = ""
)

data class Preset(
    val id: Int,
    val name: String,
    val description: String
) {
    companion object {
        val ALL_PRESETS = listOf(
            Preset(1, "file_io", "File I/O (open/read/write/close)"),
            Preset(2, "fs_ops", "Filesystem ops (mkdir/unlink/chmod)"),
            Preset(3, "network", "Network (socket/bind/connect/send)"),
            Preset(4, "process", "Process mgmt (clone/exec/exit/wait)"),
            Preset(5, "signal", "Signals (kill/sigaction/sigprocmask)"),
            Preset(6, "memory", "Memory mgmt (mmap/mprotect/brk)"),
            Preset(7, "ipc", "IPC (pipe/msg/sem/shm/futex)"),
            Preset(8, "security", "Security (seccomp/bpf/ptrace/cap)"),
            Preset(9, "all", "All syscalls (tier1 + tier2)")
        )
    }
}

object StatusParser {

    fun parseStatus(json: String): ModuleStatus {
        return try {
            val j = JSONObject(json)
            ModuleStatus(
                ok = j.optBoolean("ok", false),
                enabled = j.optBoolean("enabled", false),
                uid = j.optInt("uid", -1),
                tier2 = j.optBoolean("tier2", false),
                eventsTotal = j.optLong("eventsTotal", 0),
                eventsBuffered = j.optInt("eventsBuffered", 0),
                nrFilter = j.optString("nrFilter", ""),
                tier1Hooked = j.optBoolean("tier1Hooked", false),
                tier2Hooked = j.optBoolean("tier2Hooked", false),
                version = j.optString("version", "")
            )
        } catch (e: Exception) {
            ModuleStatus()
        }
    }

    fun parseDrain(json: String): DrainResult {
        return try {
            val j = JSONObject(json)
            val arr = j.optJSONArray("events") ?: JSONArray()
            val events = (0 until arr.length()).map { parseEvent(arr.getJSONObject(it)) }
            DrainResult(
                ok = j.optBoolean("ok", false),
                events = events,
                total = j.optLong("total", 0),
                drained = j.optInt("drained", 0),
                buffered = j.optInt("buffered", 0)
            )
        } catch (e: Exception) {
            DrainResult()
        }
    }

    fun parseEvents(json: String): DrainResult = parseDrain(json)

    fun parseSimple(json: String): SimpleResult {
        return try {
            val j = JSONObject(json)
            SimpleResult(
                ok = j.optBoolean("ok", false),
                msg = j.optString("msg", ""),
                error = j.optString("error", "")
            )
        } catch (e: Exception) {
            SimpleResult(error = e.message ?: "parse error")
        }
    }

    private fun parseEvent(j: JSONObject): SvcEvent {
        return SvcEvent(
            seq = j.optLong("seq", 0),
            nr = j.optInt("nr", 0),
            name = j.optString("name", nrToName(j.optInt("nr", 0))),
            pid = j.optInt("pid", 0),
            uid = j.optInt("uid", 0),
            comm = j.optString("comm", ""),
            a0 = j.optLong("a0", 0), a1 = j.optLong("a1", 0),
            a2 = j.optLong("a2", 0), a3 = j.optLong("a3", 0),
            a4 = j.optLong("a4", 0), a5 = j.optLong("a5", 0),
            desc = j.optString("desc", ""),
            caller = j.optString("caller", ""),
            pc = j.optString("pc", ""),
            fdPath = j.optString("fdPath", ""),
            cloneFn = j.optLong("cloneFn", 0)
        )
    }

    // ---- Syscall name resolution ----

    private val NR_NAMES = mapOf(
        0 to "io_setup", 1 to "io_destroy", 2 to "io_submit", 3 to "io_cancel",
        4 to "io_getevents", 5 to "setxattr", 8 to "getxattr", 11 to "listxattr",
        14 to "removexattr", 17 to "getcwd", 19 to "eventfd2",
        20 to "epoll_create1", 21 to "epoll_ctl", 22 to "epoll_pwait",
        23 to "dup", 24 to "dup3", 25 to "fcntl", 26 to "inotify_init1",
        27 to "inotify_add_watch", 28 to "inotify_rm_watch",
        29 to "ioctl", 32 to "flock",
        33 to "mknodat", 34 to "mkdirat", 35 to "unlinkat", 36 to "symlinkat",
        37 to "linkat", 38 to "renameat", 39 to "umount2", 40 to "mount",
        43 to "statfs", 44 to "fstatfs", 45 to "truncate", 46 to "ftruncate",
        47 to "fallocate", 48 to "faccessat", 49 to "chdir",
        52 to "fchmod", 53 to "fchmodat", 54 to "fchownat", 55 to "fchown",
        56 to "openat", 57 to "close", 59 to "pipe2",
        61 to "getdents64", 62 to "lseek", 63 to "read", 64 to "write",
        65 to "readv", 66 to "writev", 67 to "pread64", 68 to "pwrite64",
        71 to "sendfile", 72 to "pselect6", 73 to "ppoll",
        76 to "splice", 78 to "readlinkat", 79 to "newfstatat",
        80 to "fstat", 81 to "sync", 82 to "fsync", 83 to "fdatasync",
        88 to "utimensat", 93 to "exit", 94 to "exit_group", 95 to "waitid",
        96 to "set_tid_address", 97 to "unshare", 98 to "futex",
        101 to "nanosleep", 105 to "init_module", 106 to "delete_module",
        113 to "clock_gettime", 117 to "ptrace",
        129 to "kill", 130 to "tkill", 131 to "tgkill",
        134 to "rt_sigaction", 135 to "rt_sigprocmask",
        137 to "rt_sigtimedwait", 138 to "rt_sigqueueinfo",
        146 to "setuid", 147 to "setresuid", 149 to "setresgid",
        151 to "setfsuid", 152 to "setfsgid",
        154 to "setpgid", 160 to "uname", 167 to "prctl",
        172 to "getpid", 173 to "getppid", 174 to "getuid", 175 to "geteuid",
        176 to "getgid", 177 to "getegid", 178 to "gettid", 179 to "sysinfo",
        186 to "msgget", 187 to "msgctl", 188 to "msgrcv", 189 to "msgsnd",
        190 to "semget", 191 to "semctl", 192 to "semtimedop", 193 to "semop",
        194 to "shmget", 195 to "shmctl", 196 to "shmat", 197 to "shmdt",
        198 to "socket", 199 to "socketpair", 200 to "bind", 201 to "listen",
        202 to "accept", 203 to "connect", 204 to "getsockname", 205 to "getpeername",
        206 to "sendto", 207 to "recvfrom", 208 to "setsockopt", 209 to "getsockopt",
        210 to "shutdown", 211 to "sendmsg", 212 to "recvmsg",
        213 to "readahead", 214 to "brk", 215 to "munmap", 216 to "mremap",
        220 to "clone", 221 to "execve", 222 to "mmap", 226 to "mprotect",
        228 to "mlock", 229 to "munlock", 233 to "madvise",
        240 to "rt_tgsigqueueinfo", 242 to "accept4", 243 to "recvmmsg",
        260 to "wait4", 261 to "prlimit64",
        268 to "setns", 269 to "sendmmsg",
        273 to "finit_module", 276 to "renameat2", 277 to "seccomp",
        278 to "getrandom", 279 to "memfd_create", 280 to "bpf", 281 to "execveat",
        284 to "mlock2", 291 to "statx",
        425 to "io_uring_setup", 426 to "io_uring_enter", 427 to "io_uring_register",
        435 to "clone3", 436 to "close_range", 437 to "openat2", 439 to "faccessat2"
    )

    fun nrToName(nr: Int): String = NR_NAMES.getOrDefault(nr, "syscall_$nr")

    // ---- Syscall categories for UI ----

    data class SyscallEntry(val nr: Int, val name: String)
    data class SyscallCategory(val name: String, val entries: List<SyscallEntry>)

    val SYSCALL_CATEGORIES = listOf(
        SyscallCategory("File I/O", listOf(
            SyscallEntry(56, "openat"), SyscallEntry(57, "close"),
            SyscallEntry(63, "read"), SyscallEntry(64, "write"),
            SyscallEntry(62, "lseek"), SyscallEntry(82, "fsync"),
            SyscallEntry(83, "fdatasync"), SyscallEntry(71, "sendfile")
        )),
        SyscallCategory("Filesystem", listOf(
            SyscallEntry(34, "mkdirat"), SyscallEntry(35, "unlinkat"),
            SyscallEntry(53, "fchmodat"), SyscallEntry(54, "fchownat"),
            SyscallEntry(48, "faccessat"), SyscallEntry(78, "readlinkat"),
            SyscallEntry(276, "renameat2"), SyscallEntry(291, "statx")
        )),
        SyscallCategory("Network", listOf(
            SyscallEntry(198, "socket"), SyscallEntry(200, "bind"),
            SyscallEntry(203, "connect"), SyscallEntry(206, "sendto"),
            SyscallEntry(207, "recvfrom"), SyscallEntry(210, "shutdown"),
            SyscallEntry(211, "sendmsg"), SyscallEntry(212, "recvmsg")
        )),
        SyscallCategory("Process", listOf(
            SyscallEntry(220, "clone"), SyscallEntry(221, "execve"),
            SyscallEntry(93, "exit"), SyscallEntry(260, "wait4"),
            SyscallEntry(129, "kill"), SyscallEntry(131, "tgkill"),
            SyscallEntry(167, "prctl"), SyscallEntry(435, "clone3")
        )),
        SyscallCategory("Memory", listOf(
            SyscallEntry(222, "mmap"), SyscallEntry(226, "mprotect"),
            SyscallEntry(215, "munmap"), SyscallEntry(214, "brk"),
            SyscallEntry(233, "madvise"), SyscallEntry(228, "mlock")
        )),
        SyscallCategory("Security", listOf(
            SyscallEntry(277, "seccomp"), SyscallEntry(280, "bpf"),
            SyscallEntry(117, "ptrace"), SyscallEntry(273, "finit_module"),
            SyscallEntry(146, "setuid"), SyscallEntry(268, "setns")
        ))
    )
}
