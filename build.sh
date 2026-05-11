#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cat <<'EOF'
====================================================================
【你只需要改这 2 个地方】（或改成导出环境变量也行）

1) KP_DIR：KernelPatch 源码目录（必须是绝对路径）
   例：/Users/<username>/Desktop/GithubProject/SVC_Call/KernelPatch

2) ANDROID_SDK：Android SDK 目录（必须是绝对路径）
   例：/Users/<username>/Library/Android/sdk

可选：
3) JAVA_HOME：JDK 17 的 Contents/Home（如果系统找不到会要求你手动设置）
   例：/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home

不想改文件的话，也可以直接在终端执行：
  export KP_DIR=".../KernelPatch"
  export ANDROID_SDK=".../Android/sdk"
  export JAVA_HOME=".../jdk17/Contents/Home"   # 如需要
  bash build.sh
====================================================================
EOF

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN} SVC_Call One-Click Build (KPM + APK)${NC}"
echo -e "${GREEN}====================================================${NC}"
echo ""

echo -e "${YELLOW}!!! 需要你改的路径（很重要） !!!${NC}"
KP_DIR_DEFAULT="$SCRIPT_DIR/KernelPatch"
ANDROID_SDK_DEFAULT="${HOME}/Library/Android/sdk"
if [ ! -d "$ANDROID_SDK_DEFAULT" ]; then ANDROID_SDK_DEFAULT="/Users/bytedance/Library/Android/sdk"; fi

KP_DIR="${KP_DIR:-$KP_DIR_DEFAULT}"
ANDROID_SDK="${ANDROID_SDK:-$ANDROID_SDK_DEFAULT}"
echo "  KP_DIR      = $KP_DIR"
echo "  ANDROID_SDK = $ANDROID_SDK"
echo ""

if [ ! -d "$KP_DIR" ]; then
  echo -e "${RED}[ERROR]${NC} KP_DIR 未配置或目录不存在：$KP_DIR"
  echo "请把 build.sh 顶部的 KP_DIR 改成你的 KernelPatch 源码路径，或导出环境变量："
  echo "  export KP_DIR=/abs/path/to/KernelPatch"
  exit 1
fi
if [ ! -d "$ANDROID_SDK" ]; then
  echo -e "${RED}[ERROR]${NC} ANDROID_SDK 目录不存在：$ANDROID_SDK"
  echo "请把 build.sh 顶部的 ANDROID_SDK 改成你的 Android SDK 路径，或导出环境变量："
  echo "  export ANDROID_SDK=/abs/path/to/Android/sdk"
  exit 1
fi

TOOLS_DIR="$SCRIPT_DIR/.build_tools"
mkdir -p "$TOOLS_DIR"

if [ -z "${JAVA_HOME:-}" ]; then
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
    export JAVA_HOME
  fi
fi

JAVA_MAJOR=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_LINE="$("$JAVA_HOME/bin/java" -version 2>&1 | head -n 1)"
  if [[ "$JAVA_LINE" =~ \"([0-9]+)\. ]]; then
    JAVA_MAJOR="${BASH_REMATCH[1]}"
  elif [[ "$JAVA_LINE" =~ \"([0-9]+)\" ]]; then
    JAVA_MAJOR="${BASH_REMATCH[1]}"
  fi
fi

if [ -z "${JAVA_HOME:-}" ] || [ ! -d "$JAVA_HOME" ]; then
  echo -e "${YELLOW}[INFO]${NC} 未检测到 JDK 17，自动使用/下载 Temurin 17 到 $TOOLS_DIR"
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  if [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
      JDK_URL="https://api.adoptium.net/v3/binary/latest/17/ga/mac/aarch64/jdk/hotspot/normal/eclipse"
    else
      JDK_URL="https://api.adoptium.net/v3/binary/latest/17/ga/mac/x64/jdk/hotspot/normal/eclipse"
    fi
  else
    echo -e "${RED}[ERROR]${NC} 未找到 JDK 17，且暂不支持自动下载到该系统：$OS"
    echo "请安装 JDK 17 并导出："
    echo "  export JAVA_HOME=/path/to/jdk17"
    exit 1
  fi

  JDK_TGZ="$TOOLS_DIR/temurin17.tar.gz"
  JDK_EXTRACT="$TOOLS_DIR/temurin17"
  mkdir -p "$JDK_EXTRACT"
  JAVA_HOME="$(find "$JDK_EXTRACT" -type f -path "*/Contents/Home/bin/java" -print 2>/dev/null | head -n 1 | sed 's#/bin/java##')"
  if [ -z "${JAVA_HOME:-}" ] || [ ! -d "$JAVA_HOME" ]; then
    if [ ! -f "$JDK_TGZ" ]; then
      curl -L -o "$JDK_TGZ" "$JDK_URL"
    fi
    rm -rf "$JDK_EXTRACT"/*
    tar -xzf "$JDK_TGZ" -C "$JDK_EXTRACT"
    JAVA_HOME="$(find "$JDK_EXTRACT" -type f -path "*/Contents/Home/bin/java" -print 2>/dev/null | head -n 1 | sed 's#/bin/java##')"
    if [ -z "${JAVA_HOME:-}" ] || [ ! -d "$JAVA_HOME" ]; then
      echo -e "${RED}[ERROR]${NC} 自动下载 JDK 失败，请手动设置 JAVA_HOME"
      exit 1
    fi
  fi
  export JAVA_HOME
elif [ "$JAVA_MAJOR" != "17" ]; then
  echo -e "${YELLOW}[INFO]${NC} 当前 JAVA_HOME 不是 JDK17（检测到: ${JAVA_LINE}），自动切换到 Temurin 17"
  unset JAVA_HOME
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  if [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
      JDK_URL="https://api.adoptium.net/v3/binary/latest/17/ga/mac/aarch64/jdk/hotspot/normal/eclipse"
    else
      JDK_URL="https://api.adoptium.net/v3/binary/latest/17/ga/mac/x64/jdk/hotspot/normal/eclipse"
    fi
  else
    echo -e "${RED}[ERROR]${NC} 需要 JDK 17，且暂不支持自动下载到该系统：$OS"
    exit 1
  fi
  JDK_TGZ="$TOOLS_DIR/temurin17.tar.gz"
  JDK_EXTRACT="$TOOLS_DIR/temurin17"
  mkdir -p "$JDK_EXTRACT"
  JAVA_HOME="$(find "$JDK_EXTRACT" -type f -path "*/Contents/Home/bin/java" -print 2>/dev/null | head -n 1 | sed 's#/bin/java##')"
  if [ -z "${JAVA_HOME:-}" ] || [ ! -d "$JAVA_HOME" ]; then
    curl -L -o "$JDK_TGZ" "$JDK_URL"
    rm -rf "$JDK_EXTRACT"/*
    tar -xzf "$JDK_TGZ" -C "$JDK_EXTRACT"
    JAVA_HOME="$(find "$JDK_EXTRACT" -type f -path "*/Contents/Home/bin/java" -print 2>/dev/null | head -n 1 | sed 's#/bin/java##')"
    if [ -z "${JAVA_HOME:-}" ] || [ ! -d "$JAVA_HOME" ]; then
      echo -e "${RED}[ERROR]${NC} 自动下载 JDK 失败，请手动设置 JAVA_HOME"
      exit 1
    fi
  fi
  export JAVA_HOME
fi
export PATH="$JAVA_HOME/bin:$PATH"

export ANDROID_HOME="$ANDROID_SDK"
export ANDROID_SDK_ROOT="$ANDROID_SDK"

GRADLE_VERSION="${GRADLE_VERSION:-8.1.1}"
GRADLE_DIR="$TOOLS_DIR/gradle-$GRADLE_VERSION"
GRADLE_BIN="${GRADLE_BIN:-$GRADLE_DIR/bin/gradle}"

if [ ! -x "$GRADLE_BIN" ]; then
  echo -e "${YELLOW}[INFO]${NC} 未找到 Gradle，自动下载：$GRADLE_VERSION"
  ZIP="$TOOLS_DIR/gradle-$GRADLE_VERSION-bin.zip"
  URL="https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"
  rm -f "$ZIP"
  curl -L -o "$ZIP" "$URL"
  rm -rf "$GRADLE_DIR"
  unzip -q "$ZIP" -d "$TOOLS_DIR"
fi

echo -e "${YELLOW}[1/2]${NC} Building KPM (svc_monitor.kpm)..."
( cd "$SCRIPT_DIR/kpm" && make clean all KP_DIR="$KP_DIR" SDK_DIR="$ANDROID_SDK" )
KPM_OUT="$SCRIPT_DIR/kpm/svc_monitor.kpm"
if [ ! -f "$KPM_OUT" ]; then
  echo -e "${RED}[ERROR]${NC} KPM 构建失败：未找到产物 $KPM_OUT"
  exit 1
fi
echo -e "${GREEN}[OK]${NC} KPM → $KPM_OUT"

echo -e "${YELLOW}[2/2]${NC} Building APK (app-debug.apk)..."
( cd "$SCRIPT_DIR/android" && "$GRADLE_BIN" -p . :app:assembleDebug --no-daemon -Dkotlin.daemon.enabled=false )
APK_OUT="$SCRIPT_DIR/android/app/build/outputs/apk/debug/app-debug.apk"
if [ ! -f "$APK_OUT" ]; then
  echo -e "${RED}[ERROR]${NC} APK 构建失败：未找到产物 $APK_OUT"
  exit 1
fi
echo -e "${GREEN}[OK]${NC} APK → $APK_OUT"

echo ""
echo -e "${GREEN}==================== DONE ====================${NC}"
echo "KPM: $KPM_OUT"
echo "APK: $APK_OUT"
echo ""
echo "Deploy KPM:"
echo "  adb push \"$KPM_OUT\" /data/local/tmp/svc_monitor.kpm"
echo "  adb shell su -c '/data/adb/kpatch <SUPERKEY> kpm load /data/local/tmp/svc_monitor.kpm'"
echo ""
echo "Install APK:"
echo "  adb install -r \"$APK_OUT\""
