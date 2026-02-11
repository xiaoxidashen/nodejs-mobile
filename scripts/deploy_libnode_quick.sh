#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy_libnode_quick.sh [options]

Options:
  --serial <id>          Use specific adb device serial. Default: first online device.
  --adb <path>           adb executable path. Default: auto detect adb.exe / adb.
  --ndk <path>           Android NDK path. Default: $ANDROID_NDK_HOME / $ANDROID_NDK_ROOT / /root/android-ndk/android-ndk-r24
  --sdk <api>            Android API level used by android-configure. Default: 24
  --force-configure      Force rerun android-configure before build.
  --no-sccache           Disable sccache integration for this run.
  --install              Install/update apk_generator debug before verify.
  --jobs <n>             Make jobs. Default: nproc
  --apk-generator-dir    apk_generator repo path. Default: /mnt/d/Code/Android/Projects/apk_generator
  --package <name>       App package name. Default: org.tempbox.apk_generator
  --provider <auth>      ContentProvider authority. Default: org.tempbox.apk_generator.devbridge
  --method <name>        Provider method. Default: node_probe
  -h, --help             Show this help.

Flow:
  1) Detect online device ABI (must be x86_64)
  2) Incremental build libnode.so for that ABI
  3) Patch .text hash slot
  4) Sync to apk_generator/app/libnode/bin/<abi>/libnode.so
  5) (Optional) install apk_generator debug app (--install)
  6) Root-swap installed app lib: codePath/lib/<abi>/libnode.so
  7) Verify by ContentProvider.call(node_probe)
USAGE
}

SERIAL=""
ADB_BIN=""
NDK_PATH="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/root/android-ndk/android-ndk-r24}}"
SDK_API="24"
APK_GENERATOR_DIR="/mnt/d/Code/Android/Projects/apk_generator"
PACKAGE_NAME="org.tempbox.apk_generator"
PROVIDER_AUTHORITY="org.tempbox.apk_generator.devbridge"
PROVIDER_METHOD="node_probe"
FORCE_CONFIGURE="0"
USE_SCCACHE="1"
INSTALL_APK="0"

if command -v nproc >/dev/null 2>&1; then
  JOBS="$(nproc)"
else
  JOBS="4"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      SERIAL="${2:-}"
      shift 2
      ;;
    --adb)
      ADB_BIN="${2:-}"
      shift 2
      ;;
    --ndk)
      NDK_PATH="${2:-}"
      shift 2
      ;;
    --sdk)
      SDK_API="${2:-}"
      shift 2
      ;;
    --force-configure)
      FORCE_CONFIGURE="1"
      shift
      ;;
    --no-sccache)
      USE_SCCACHE="0"
      shift
      ;;
    --install)
      INSTALL_APK="1"
      shift
      ;;
    --jobs)
      JOBS="${2:-}"
      shift 2
      ;;
    --apk-generator-dir)
      APK_GENERATOR_DIR="${2:-}"
      shift 2
      ;;
    --package)
      PACKAGE_NAME="${2:-}"
      shift 2
      ;;
    --provider)
      PROVIDER_AUTHORITY="${2:-}"
      shift 2
      ;;
    --method)
      PROVIDER_METHOD="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ADB_BIN" ]]; then
  if command -v adb.exe >/dev/null 2>&1; then
    ADB_BIN="adb.exe"
  elif command -v adb >/dev/null 2>&1; then
    ADB_BIN="adb"
  else
    echo "adb/adb.exe not found in PATH." >&2
    exit 1
  fi
fi

if [[ -z "$SERIAL" ]]; then
  SERIAL="$($ADB_BIN devices | tr -d '\r' | awk 'NR > 1 && $2 == "device" {print $1; exit}')"
fi

if [[ -z "$SERIAL" ]]; then
  echo "No online adb device found." >&2
  exit 1
fi

ADB=("$ADB_BIN" -s "$SERIAL")

echo "[info] adb: $ADB_BIN"
echo "[info] serial: $SERIAL"

ABI="$(${ADB[@]} shell getprop ro.product.cpu.abi | tr -d '\r')"
if [[ -z "$ABI" ]]; then
  echo "Cannot detect device ABI." >&2
  exit 1
fi
echo "[info] device abi: $ABI"

if [[ "$ABI" != "x86_64" ]]; then
  echo "Unsupported device ABI for this quick script: $ABI (expected x86_64)." >&2
  exit 1
fi

TARGET_ARCH="x86_64"
ABI_DIR="x86_64"

echo "[info] target arch: $TARGET_ARCH"

if [[ ! -d "$NDK_PATH" ]]; then
  echo "NDK path not found: $NDK_PATH" >&2
  exit 1
fi

if [[ "$USE_SCCACHE" == "1" ]]; then
  if ! command -v sccache >/dev/null 2>&1 && [[ -x "$HOME/.cargo/bin/sccache" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  if command -v sccache >/dev/null 2>&1; then
    export SCCACHE_PATH="$(command -v sccache)"
    export SCCACHE_IGNORE_SERVER_IO_ERROR="1"
    echo "[info] sccache: $SCCACHE_PATH"
    sccache --start-server >/dev/null 2>&1 || true
    sccache --zero-stats >/dev/null 2>&1 || true
  else
    echo "[warn] sccache not found in PATH; falling back to direct compiler." >&2
  fi
fi

if [[ ! -d "$APK_GENERATOR_DIR" ]]; then
  echo "apk_generator dir not found: $APK_GENERATOR_DIR" >&2
  exit 1
fi

OUT_DIR="out_android/$ABI_DIR"
mkdir -p "$OUT_DIR"
SO_OUT="$OUT_DIR/libnode.so"
CFG_STAMP="$OUT_DIR/.quick_build_config"
CFG_VALUE="arch=$TARGET_ARCH;ndk=$NDK_PATH;sdk=$SDK_API"

NEED_CONFIGURE="0"
if [[ "$FORCE_CONFIGURE" == "1" ]]; then
  NEED_CONFIGURE="1"
elif [[ ! -f "out/Makefile" ]]; then
  NEED_CONFIGURE="1"
elif [[ ! -f "$CFG_STAMP" ]]; then
  NEED_CONFIGURE="1"
else
  LAST_CFG="$(cat "$CFG_STAMP" 2>/dev/null || true)"
  if [[ "$LAST_CFG" != "$CFG_VALUE" ]]; then
    NEED_CONFIGURE="1"
  fi
fi

if [[ "$NEED_CONFIGURE" == "1" ]]; then
  echo "[step] android-configure (needed)"
  ./android-configure "$NDK_PATH" "$SDK_API" "$TARGET_ARCH"
  printf '%s\n' "$CFG_VALUE" > "$CFG_STAMP"
else
  echo "[step] android-configure skipped (same arch/ndk/sdk)"
fi

echo "[step] build libnode.so (incremental target=libnode)"
make -C out BUILDTYPE=Release V=0 -j"$JOBS" libnode

if [[ "$USE_SCCACHE" == "1" ]] && command -v sccache >/dev/null 2>&1; then
  echo "[info] sccache stats:"
  sccache --show-stats || true
fi

SO_SRC=""
if [[ -f "out/Release/lib.target/libnode.so" ]]; then
  SO_SRC="out/Release/lib.target/libnode.so"
elif [[ -f "out/Release/obj.target/libnode.so" ]]; then
  SO_SRC="out/Release/obj.target/libnode.so"
else
  echo "Cannot find built libnode.so in out/Release." >&2
  exit 1
fi

echo "[info] source so: $SO_SRC"
cp -f "$SO_SRC" "$SO_OUT"

echo "[step] patch .text hash slot"
python tools/patch_so_text_hash.py --so "$SO_OUT" --no-backup

APK_LIB_DIR="$APK_GENERATOR_DIR/app/libnode/bin/$ABI_DIR"
mkdir -p "$APK_LIB_DIR"
cp -f "$SO_OUT" "$APK_LIB_DIR/libnode.so"
echo "[step] synced to $APK_LIB_DIR/libnode.so"

if [[ "$INSTALL_APK" == "1" ]]; then
  echo "[step] install apk_generator debug"
  if command -v wslpath >/dev/null 2>&1 && command -v cmd.exe >/dev/null 2>&1; then
    # Start cmd.exe from a Windows-mounted path to avoid UNC cwd warning.
    (
      cd "$APK_GENERATOR_DIR"
      cmd.exe /c "gradlew.bat :app:installDebug -x lint -x test"
    )
  else
    (cd "$APK_GENERATOR_DIR" && ./gradlew :app:installDebug -x lint -x test)
  fi
else
  echo "[step] install apk_generator debug skipped (use --install when app code changed)"
fi

TOKEN="nodeprobe-$(date +%s)-$$"
URI="content://$PROVIDER_AUTHORITY"
DEVICE_TMP_SO="/data/local/tmp/libnode.quick.${SERIAL}.so"
PROVIDER_PROCESS="${PACKAGE_NAME}:devbridge"
TARGET_SO=""
LOCAL_HASH=""
TARGET_HASH=""

echo "[step] check su availability"
if ! ${ADB[@]} shell "su -c id" >/dev/null 2>&1; then
  echo "su is not available; root-swap mode cannot continue." >&2
  exit 1
fi

echo "[step] resolve installed app lib path"
CODE_PATH="$(${ADB[@]} shell "dumpsys package '$PACKAGE_NAME' | grep -m1 'codePath=' | sed 's/^.*codePath=//'" | tr -d '\r')"
if [[ -z "$CODE_PATH" ]]; then
  echo "Cannot resolve codePath for $PACKAGE_NAME." >&2
  exit 1
fi
TARGET_SO="$CODE_PATH/lib/$ABI_DIR/libnode.so"
echo "[info] target so: $TARGET_SO"

echo "[step] push built so to device temp path"
${ADB[@]} push "$SO_OUT" "$DEVICE_TMP_SO" >/dev/null

echo "[step] root-swap installed libnode.so"
${ADB[@]} shell "su -c 'cp \"$DEVICE_TMP_SO\" \"$TARGET_SO\" && chown system:system \"$TARGET_SO\" && chmod 755 \"$TARGET_SO\" && (restorecon \"$TARGET_SO\" || true) && ls -l \"$TARGET_SO\"'" | tr -d '\r'
${ADB[@]} shell "rm -f '$DEVICE_TMP_SO'" >/dev/null 2>&1 || true

LOCAL_HASH="$(sha256sum "$SO_OUT" | awk '{print $1}')"
TARGET_HASH="$(${ADB[@]} shell "su -c 'sha256sum \"$TARGET_SO\"'" | tr -d '\r' | awk '{print $1}')"
echo "[info] local sha256:  $LOCAL_HASH"
echo "[info] target sha256: $TARGET_HASH"
if [[ -z "$TARGET_HASH" || "$LOCAL_HASH" != "$TARGET_HASH" ]]; then
  echo "Root-swap hash verification failed." >&2
  exit 1
fi

echo "[step] force-stop app to reset provider process"
${ADB[@]} shell "am force-stop '$PACKAGE_NAME'"

echo "[step] ensure $PROVIDER_PROCESS is stopped"
for _ in 1 2 3 4 5; do
  DEVBRIDGE_PID="$(${ADB[@]} shell "pidof '$PROVIDER_PROCESS' 2>/dev/null || true" | tr -d '\r' | tr -d '[:space:]')"
  if [[ -z "$DEVBRIDGE_PID" ]]; then
    break
  fi
  ${ADB[@]} shell "kill -9 $DEVBRIDGE_PID" >/dev/null 2>&1 || true
  sleep 0.2
done

DEVBRIDGE_PID="$(${ADB[@]} shell "pidof '$PROVIDER_PROCESS' 2>/dev/null || true" | tr -d '\r' | tr -d '[:space:]')"
if [[ -n "$DEVBRIDGE_PID" ]]; then
  echo "Failed to stop $PROVIDER_PROCESS (pid=$DEVBRIDGE_PID)." >&2
  exit 1
fi

echo "[step] verify by ContentProvider.call ($URI, method=$PROVIDER_METHOD)"
PROVIDER_OUT="$(${ADB[@]} shell "content call --uri '$URI' --method '$PROVIDER_METHOD' --arg '$TOKEN'" | tr -d '\r')"
printf '%s\n' "$PROVIDER_OUT"

if [[ "$PROVIDER_OUT" == *"ok=true"* ]] && [[ "$PROVIDER_OUT" == *"$TOKEN"* ]]; then
  echo "[ok] node probe verification: pass"
else
  echo "[fail] node probe verification failed." >&2
  exit 1
fi

echo "[done] libnode deployed and verified for abi=$ABI_DIR"
