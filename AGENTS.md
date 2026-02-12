# AGENTS.md

## 作用范围
- 本仓库用于构建 Android 的 `libnode.so`。
- 在 `apk_generator` 中，最终从 `app/libnode/bin/<abi>/libnode.so` 被打包使用。

## 快速测试脚本（libnode）
- 脚本：`scripts/deploy_libnode_quick.sh`
- 作用：按设备 ABI 增量构建 `libnode.so`，回填 `.text` hash，`su` 覆盖已安装 App 的 `codePath/lib/<abi>/libnode.so`，并通过 `ContentProvider.call(node_probe)` 做进程内验证。
- 默认构建配置：
  - NDK：`/root/android-ndk/android-ndk-r24`
  - SDK：`24`
  - ABI：当前脚本仅支持 `x86_64` 设备
- 常用参数：
  - `--serial` `--adb` `--ndk` `--sdk` `--force-configure` `--no-sccache` `--install`
- 示例：
  - `scripts/deploy_libnode_quick.sh --adb adb.exe`
  - `scripts/deploy_libnode_quick.sh --adb adb.exe --install`

## 常改入口
- `node.gyp`
  - `libnode.so` 的核心目标是 `target_name: <(node_lib_target_name)`。
  - Android 专属源码通常通过 `conditions` 注入（例如 `OS=="android"`）。
- `src/apk_guard.c`
  - APK 签名校验逻辑（`constructor` 自动执行，V2/V1 证书指纹校验）。
- `src/so_self_integrity.c`
  - SO 自校验逻辑（运行时计算 `.text` SHA-256 与槽位值比对）。
- `android_configure.py`
  - Android 交叉编译工具链、`GYP_DEFINES`、`--shared` 等配置。
- `tools/android_build.sh`
  - Android 一键构建脚本，以及 `libnode.so` 产物拷贝逻辑。
- `tools/patch_so_text_hash.py`
  - 编译后回填 `.text` hash 到 `so_self_integrity.c` 的槽位。
- `tools/parse_sccache_compile_requests.py`
  - 解析 `sccache --show-stats --stats-format=json`，提取 `compile_requests`。
- `common.gypi` / `node.gypi`
  - Android 全局编译/链接行为调整时会改到这里。

## 当前签名校验接入（重要）
- 守护源码文件：`src/apk_guard.c`。
- 自校验源码文件：`src/so_self_integrity.c`。
- 日志默认强制关闭（避免运行时打印）：
  - `#ifndef AG_NO_LOG`
  - `#define AG_NO_LOG 1`
  - `#endif`
- `node.gyp` 已按 Android 条件注入：
  - `OS=="android"` 时把 `src/apk_guard.c` 与 `src/so_self_integrity.c` 加入 `sources`。
- 回填脚本：
  - `tools/patch_so_text_hash.py --so <path/to/libnode.so> --no-backup`

## 构建与产物
- 构建命令：
  - `./tools/android_build.sh <ndk_path> <sdk_version> [target_arch]`
- 输出目录：
  - `out_android/armeabi-v7a/libnode.so`
  - `out_android/arm64-v8a/libnode.so`
  - `out_android/x86_64/libnode.so`
- 头文件拷贝脚本：
  - `tools/copy_libnode_headers.sh android`
- GitHub Actions：
  - `.github/workflows/build-mobile.yml` 在 upload 前自动回填 `out_android/**/libnode.so` 的 `.text` hash。
  - `build-android` 启用 sccache；`Validate sccache backend` 会先探测缓存后端可用性。
  - 若 GHA cache 后端异常，会写入 `SCCACHE_GHA_ENABLED=false` 自动降级到本地 sccache，避免构建直接失败。
  - 全局设置 `SCCACHE_IGNORE_SERVER_IO_ERROR=1`，缓存 I/O 异常时优先回退到直编而非失败。
  - 统计步骤 `Report sccache stats` 使用 `tools/parse_sccache_compile_requests.py` 读取 `compile_requests`。
  - 当前 workflow 仅包含 Android（`build-android` / `combine-android`），不编译 iOS。

## 回灌到 apk_generator
- 将生成的 `.so` 覆盖到：
  - `D:/Code/Android/Projects/apk_generator/app/libnode/bin/<abi>/libnode.so`

## 快速定位命令
- `rg -n "node_lib_target_name|OS==\\\"android\\\"|apk_guard" node.gyp`
- `rg -n "node_lib_target_name|OS==\\\"android\\\"|apk_guard|so_self_integrity" node.gyp`
- `rg -n "AG_NO_LOG|ag_schedule_exit|constructor|AG_OBF_FP" src/apk_guard.c`
- `rg -n "AG_SI_HASH_SLOT|constructor|.text|hash mismatch" src/so_self_integrity.c`
- `rg -n "patch_so_text_hash|libnode.so" .github/workflows/build-mobile.yml tools/patch_so_text_hash.py`
- `rg -n "deploy_libnode_quick|root-swap|node_probe|codePath/lib|sccache" scripts/deploy_libnode_quick.sh`
