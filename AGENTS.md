# AGENTS.md

## 作用范围
- 本仓库用于构建 Android 的 `libnode.so`。
- 在 `apk_generator` 中，最终从 `app/libnode/bin/<abi>/libnode.so` 被打包使用。

## 常改入口
- `node.gyp`
  - `libnode.so` 的核心目标是 `target_name: <(node_lib_target_name)`。
  - Android 专属源码通常通过 `conditions` 注入（例如 `OS=="android"`）。
- `src/apk_guard.c`
  - APK 签名校验逻辑（`constructor` 自动执行，V2/V1 证书指纹校验）。
- `android_configure.py`
  - Android 交叉编译工具链、`GYP_DEFINES`、`--shared` 等配置。
- `tools/android_build.sh`
  - Android 一键构建脚本，以及 `libnode.so` 产物拷贝逻辑。
- `common.gypi` / `node.gypi`
  - Android 全局编译/链接行为调整时会改到这里。

## 当前签名校验接入（重要）
- 守护源码文件：`src/apk_guard.c`。
- 日志默认强制关闭（避免运行时打印）：
  - `#ifndef AG_NO_LOG`
  - `#define AG_NO_LOG 1`
  - `#endif`
- `node.gyp` 已按 Android 条件注入：
  - `OS=="android"` 时把 `src/apk_guard.c` 加入 `sources`。

## 构建与产物
- 构建命令：
  - `./tools/android_build.sh <ndk_path> <sdk_version> [target_arch]`
- 输出目录：
  - `out_android/armeabi-v7a/libnode.so`
  - `out_android/arm64-v8a/libnode.so`
  - `out_android/x86_64/libnode.so`
- 头文件拷贝脚本：
  - `tools/copy_libnode_headers.sh android`

## 回灌到 apk_generator
- 将生成的 `.so` 覆盖到：
  - `D:/Code/Android/Projects/apk_generator/app/libnode/bin/<abi>/libnode.so`

## 快速定位命令
- `rg -n "node_lib_target_name|OS==\\\"android\\\"|apk_guard" node.gyp`
- `rg -n "AG_NO_LOG|ag_schedule_exit|constructor|AG_OBF_FP" src/apk_guard.c`
