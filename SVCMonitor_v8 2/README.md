# SVCMonitor v8.3.0

ARM64 SVC system-call monitor for **Pixel 6 / Android 12 / kernel 5.10.43**.
Implemented as a KernelPatch Module (KPM) with a companion Android APP.

## Architecture

```
┌──────────────┐    CTL0 Command     ┌─────────────────┐
│  Android APP │ ──────────────────→ │  KPM Module      │
│  (Kotlin)    │    3-Phase I/O      │  svc_monitor.c   │
│              │ ←────────────────── │  (kernel space)  │
└──────────────┘    JSON via file    └─────────────────┘
```

### CTL0 3-Phase Protocol
1. **Phase 1**: Remove old output file
2. **Phase 2**: `kpatch <superkey> kpm ctl0 svc_monitor '<command>'`
3. **Phase 3**: Read JSON result from `/data/local/tmp/svc_output.json`

## Features

### Kernel Module (svc_monitor.c)
- **69 syscall hooks** (44 tier1 + 25 tier2)
- **Deep argument parsing** for 50+ syscalls with human-readable descriptions
- **Ring buffer** (1024 events) with monotonic sequence numbers
- **Bitmap NR filter** (512-bit) for selective monitoring
- **9 presets**: file_io, fs_ops, network, process, signal, memory, ipc, security, all
- **Caller address recording** (LR / x30)
- **fd→path resolution** via /proc/self/fd readlink
- **clone function pointer** capture
- **UID-based filtering**
- **JSON output** via raw_syscall file I/O
- **Lock-free design** (no mutex/spinlock)
- **All static allocation** (no kmalloc/kfree)

### Android APP (6 Kotlin files)
- **4-tab programmatic UI**: Control | Events | Filter | Settings
- **No XML layouts** -- all views created in code
- **CSV & JSON log export** with FileProvider sharing
- **App picker** for UID-based filtering
- **Syscall category toggles** for easy NR selection
- **Tier2 on-demand hooks** toggle
- **SuperKey configuration**

## Symbol Safety

Every symbol used in the kernel module is verified safe:

| Category | Symbols | Source |
|----------|---------|--------|
| KPM SDK | `hook_syscalln`, `unhook_syscall`, `compat_copy_from_user`, `raw_syscall0-6`, `current_uid` | kpmodule.h |
| Kernel exports | `printk`, `snprintf`, `strlen`, `strcmp`, `strncmp` | linux/printk.h, linux/string.h |
| Compiler builtins | `__builtin_memset`, `__builtin_memcpy` | GCC intrinsic |
| Static functions | 28 functions defined in svc_monitor.c | local |

**Forbidden symbols NOT used**: kmalloc, kfree, mutex_*, spin_lock_*, proc_create, filp_open, kthread_*, IS_ERR, d_path, etc.

## Build

### Kernel Module
```bash
cd kpm
make KPM_DIR=/path/to/KernelPatchModule
```

### Android APP
```bash
./gradlew assembleRelease
```

## File Structure

```
SVCMonitor_v8/
├── README.md
├── build.gradle.kts              # Root Gradle (AGP 8.1.0, Kotlin 1.9.0)
├── settings.gradle.kts           # Plugin management
├── gradle.properties             # AndroidX config
├── kpm/
│   ├── Makefile                  # KPM build
│   └── src/
│       └── svc_monitor.c        # Kernel module (1520 lines)
└── app/
    ├── build.gradle.kts          # App module config
    ├── proguard-rules.pro
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/svcmonitor/app/
        │   ├── KpmBridge.kt     # CTL0 protocol implementation
        │   ├── StatusParser.kt  # JSON parsing + data classes
        │   ├── LogExporter.kt   # CSV/JSON export + sharing
        │   ├── AppResolver.kt   # Package manager wrapper
        │   ├── MainViewModel.kt # AndroidViewModel state holder
        │   └── MainActivity.kt  # 4-tab programmatic UI
        └── res/
            ├── values/strings.xml
            └── xml/file_paths.xml
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `enable` | Start monitoring |
| `disable` | Stop monitoring |
| `status` | Get module status JSON |
| `uid <N>` | Set UID filter (0=all) |
| `enable_nr <N>` | Enable specific syscall NR |
| `disable_nr <N>` | Disable specific syscall NR |
| `set_nrs <N1,N2,...>` | Set exact NR filter list |
| `enable_all_nr` | Enable all NR monitoring |
| `disable_all_nr` | Disable all NR monitoring |
| `preset <1-9>` | Apply preset filter |
| `tier2 <0\|1>` | Enable/disable tier2 hooks |
| `drain` | Drain events + clear buffer |
| `events` | Read events (keep buffer) |
| `clear` | Clear event buffer |

## Version History

- **v8.3.0**: Full symbol audit, all broken symbols fixed, complete rewrite
- **v8.2**: Added caller address, fd→path, clone fn capture
- **v8.1**: Deep argument parsing for 50+ syscalls, log export
- **v8.0**: Initial KPM implementation with CTL0 protocol
