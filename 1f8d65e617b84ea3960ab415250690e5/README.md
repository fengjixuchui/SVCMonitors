# SVC Monitor v9.0

ARM64 Syscall (SVC) real-time monitor for KernelPatch (KPM).
Target: Pixel 6 / Android 12 / kernel 5.10.43

## Architecture

### Kernel Module (kpm/src/svc_monitor.c)
- **1413 lines** of C code for KPM framework
- **Dual hook strategy**: inline_hook_syscalln first, fp_hook_syscalln fallback
- **69 syscalls**: 44 tier1 + 25 tier2
- **9 presets**: file_io, fs_ops, network, process, signal, memory, ipc, security, all
- **Lock-free ring buffer** (4096 entries, kp_malloc allocated)
- **CTL0 command protocol**: enable/disable/status/drain/events/preset/setuid/tier2/clear

### v9 New Features
1. **Caller SO+Offset Resolution**: Parses /proc/<pid>/maps to resolve caller address
   to library name + file offset (e.g., libc.so+0x1a2b4) or [anon:0x7f...]
2. **File Path Resolution**: Resolves fd arguments to full paths via /proc/<pid>/fd/<N>
3. **Clone Function Pointer**: Captures and displays the function pointer passed to clone/clone3
4. **Sockaddr Parsing**: Decodes connect/bind sockaddr to IP:port or UNIX path
5. **Execve Argv Capture**: Shows first 3 argv strings for execve calls
6. **Mmap Flags Decode**: Human-readable prot and flags for mmap calls

### KPM SDK Symbols Used
- Hook: inline_hook_syscalln, fp_hook_syscalln, inline_unhook_syscalln, fp_unhook_syscalln
- Memory: kp_malloc, kp_free
- User access: compat_strncpy_from_user, compat_copy_from_user, compat_copy_to_user
- Kernel: kallsyms_lookup_name, current_uid()
- Raw syscalls: raw_syscall0-6
- Module: KPM_INIT, KPM_CTL0, KPM_EXIT

### Android APP (app/)
- **Material Design 3** with day/night theme support
- **One-click monitoring**: Quick Start dialog with UID + preset selection
- **Real-time event stream**: RecyclerView with DiffUtil, category color-coding
- **Category filter chips**: Filter by File I/O, Network, Process, etc.
- **Event detail bottom sheet**: Full argument display with caller/path info
- **CSV export** with share intent
- **Settings**: SuperKey, UID, Tier2 toggle

## Files

### Kernel Module
- kpm/src/svc_monitor.c - Main kernel module (1413 lines)
- kpm/Makefile - Build configuration

### Android APP
- app/src/main/java/com/svcmonitor/app/
  - MainActivity.kt - Main UI with Material Design 3
  - SvcViewModel.kt - ViewModel with LiveData state management
  - EventAdapter.kt - RecyclerView adapter with DiffUtil
  - KpmBridge.kt - CTL0 3-phase protocol bridge
  - StatusParser.kt - JSON parsing + data classes
  - LogExporter.kt - CSV export
  - AppResolver.kt - Package UID resolver
- app/src/main/res/layout/
  - activity_main.xml - Main layout with Toolbar, ChipGroup, RecyclerView, FAB
  - item_event.xml - Event card with category color bar
  - dialog_quick_start.xml - Quick start monitoring dialog
  - dialog_event_detail.xml - Bottom sheet event details
  - dialog_settings.xml - Settings dialog
- app/src/main/res/values/ - Colors, themes, strings
- app/src/main/res/values-night/ - Dark theme colors
- app/src/main/res/drawable/ - Status bar backgrounds
- app/src/main/res/menu/ - Options menu

## Build

### Kernel Module
Requires KernelPatch build environment:
```bash
cd kpm && make
```

### Android APP
```bash
./gradlew assembleRelease
```

## Usage

1. Load KPM module: `kpatch <superkey> kpm load svc_monitor.kpm`
2. Install and open the Android APP
3. Tap "Monitor" FAB -> set target UID and preset -> Start
4. Events stream in real-time with caller info, file paths, etc.

## SuperKey
Default: testkey (change in Settings)
