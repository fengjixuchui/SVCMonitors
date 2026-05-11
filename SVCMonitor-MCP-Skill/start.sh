#!/bin/bash
# SVC Monitor MCP 快速启动脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SUPER_KEY="${KPATCH_KEY:-XiaoLu0129}"
MODULE_NAME="svc_monitor"
OUT_FILE="/data/local/tmp/svc_out.json"
CTL0_RESOLVED=""
CTL0_CANDIDATES=(
    "/data/local/tmp/kpmctl {KEY} ctl0 {MODULE} '{CMD}'"
    "/data/adb/ap/bin/kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'"
    "/data/adb/kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'"
    "/data/adb/kpatch/bin/kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'"
    "kpatch {KEY} kpm ctl0 {MODULE} '{CMD}'"
    "kpatch-android {KEY} kpm ctl0 {MODULE} '{CMD}'"
)

build_ctl0_cmd() {
    local template="$1"
    local cmd="$2"
    local built="${template//\{KEY\}/$SUPER_KEY}"
    built="${built//\{MODULE\}/$MODULE_NAME}"
    built="${built//\{CMD\}/$cmd}"
    printf '%s' "$built"
}

try_ctl0() {
    local cmd="$1"
    local output=""
    local template=""
    local order=()

    if [[ -n "$CTL0_RESOLVED" ]]; then
        order+=("$CTL0_RESOLVED")
    fi
    for template in "${CTL0_CANDIDATES[@]}"; do
        if [[ "$template" != "$CTL0_RESOLVED" ]]; then
            order+=("$template")
        fi
    done

    for template in "${order[@]}"; do
        adb shell su -c "rm -f $OUT_FILE" >/dev/null 2>&1 || true
        adb shell su -c "$(build_ctl0_cmd "$template" "$cmd")" >/dev/null 2>&1 || true
        output="$(adb shell su -c "cat $OUT_FILE 2>/dev/null" | tr -d '\r')"
        if echo "$output" | grep -q '"ok"'; then
            CTL0_RESOLVED="$template"
            printf '%s' "$output"
            return 0
        fi
    done

    return 1
}

# 检查依赖
check_deps() {
    echo "🔍 检查依赖..."

    if ! command -v python3 &>/dev/null; then
        echo "❌ python3 未安装"
        exit 1
    fi

    if ! command -v adb &>/dev/null; then
        echo "❌ adb 未安装，请安装 Android Platform Tools"
        exit 1
    fi

    # 检查 adb 连接
    if ! adb devices | grep -q "device$"; then
        echo "⚠️  未检测到 ADB 设备，请确认 USB 连接"
    else
        echo "✅ ADB 设备已连接"
    fi

    # 检查 Python 依赖
    if ! python3 -c "import mcp" 2>/dev/null; then
        echo "📦 安装 Python 依赖..."
        pip3 install --user --break-system-packages -r requirements.txt
    fi

    echo "✅ 依赖检查完成"
}

# 检查 KPM 模块状态
check_kpm() {
    echo "🔍 检查 KPM 模块..."

    local result
    result="$(try_ctl0 "status" || true)"

    if echo "$result" | grep -q '"ok"'; then
        echo "✅ KPM svc_monitor 模块已加载"
        echo "   $result"
        if [[ -n "$CTL0_RESOLVED" ]]; then
            echo "✅ 已探测到可用控制入口: $CTL0_RESOLVED"
        fi
    else
        echo "⚠️  KPM 模块未响应，请确认:"
        echo "   1. KernelPatch/APatch 已安装"
        echo "   2. svc_monitor.kpm 已通过 APatch Manager 加载"
        echo "   3. 手机已授权 root"
        echo "   4. 当前设备可用入口可能不是旧的 /data/adb/ap/bin/kpatch"
    fi
}

# 设置 adb forward（用于 TCP 事件流）
setup_forward() {
    echo "🔗 设置 ADB 端口转发..."
    adb forward tcp:8080 tcp:8080 2>/dev/null && echo "✅ tcp:8080 已转发" || true
}

# 启动 MCP Server (stdio 模式)
start_stdio() {
    echo "🚀 启动 SVC Monitor MCP (stdio 模式)..."
    exec python3 svc_monitor_mcp.py
}

# 启动 MCP Server (SSE 模式)
start_sse() {
    local port=${1:-3001}
    echo "🚀 启动 SVC Monitor MCP (SSE 模式, 端口 $port)..."
    exec python3 svc_monitor_sse.py --port "$port"
}

# 主入口
case "${1:-stdio}" in
    check)
        check_deps
        check_kpm
        ;;
    stdio)
        check_deps
        setup_forward
        start_stdio
        ;;
    sse)
        check_deps
        setup_forward
        start_sse "${2:-3001}"
        ;;
    forward)
        setup_forward
        ;;
    status)
        check_kpm
        ;;
    *)
        echo "SVC Monitor MCP 启动器"
        echo ""
        echo "用法: $0 [命令]"
        echo ""
        echo "命令:"
        echo "  check    - 检查所有依赖和连接状态"
        echo "  stdio    - 启动 MCP Server (stdio 模式, 默认)"
        echo "  sse [port] - 启动 MCP Server (SSE HTTP 模式)"
        echo "  forward  - 设置 ADB 端口转发"
        echo "  status   - 检查 KPM 模块状态"
        ;;
esac
