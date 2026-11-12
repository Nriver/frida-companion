# Frida Auth

一个 KernelSU 模块：**按 App 授权 frida-server 的目标**，只有白名单里的 App 允许被 frida 附加/注入。

- 模块 ID：`frida-auth`
- 安装目录：`/data/adb/modules/frida-auth`
- 运行数据：`/data/adb/frida-auth`
- 支持 ABI：`arm64-v8a`、`armeabi-v7a`、`x86_64`、`x86`

## 原理

frida-server 的 agent 通信不走 27042 控制端口，而是通过注入阶段传入的 Unix socket，
所以单纯用 iptables 按端口/UID 过滤并不可靠。

本模块使用一个 `LD_PRELOAD` shim（`libfrida_auth.so`）加载进 `frida-server` 和
`frida-helper`，在以下调用发生前检查目标进程 UID：

- `ptrace`（ATTACH / SEIZE / INTERRUPT / SETOPTIONS）
- `pidfd_open` / `pidfd_getfd`
- `process_vm_readv` / `process_vm_writev`
- `open` / `openat` 打开 `/proc/<pid>/mem`

目标 UID 不在白名单时返回 `EPERM`，frida 就无法 attach/spawn 进去。

- `uid 0`（root）和 `uid 2000`（shell）始终放行，保证 server 与 helper 正常通信
- shim 只在 root 进程中生效；如果目标 App 意外继承了 `LD_PRELOAD`，会自动休眠，不影响 App
- 白名单修改后立即生效，不需要重启

## 目录结构

```
ksu-frida-auth/
├── module.prop
├── customize.sh                 # KernelSU 安装脚本
├── service.sh                   # 开机解析 UID，按需启动
├── uninstall.sh
├── sepolicy.rule                # frida 传输所需的最小 SELinux 规则
├── bin/frida-auth               # 命令行工具
├── src/frida_auth.c             # LD_PRELOAD shim 源码
├── lib/<abi>/libfrida_auth.so   # 编译产物（由 build.py 生成）
├── webroot/index.html           # KernelSU WebUI
├── build.py                     # 编译 + 打包
└── dist/                        # 打包输出（已 gitignore）
```

## 构建

需要 Android NDK（脚本会自动查找 `ANDROID_NDK_HOME`、`ANDROID_NDK_ROOT` 或
`~/Android/Sdk/ndk` 下最新版本）。

```sh
python3 ksu-frida-auth/build.py
```

输出：

```
ksu-frida-auth/dist/frida-auth-<version>.zip
```

## 安装

1. 把 zip 传到手机，例如：

   ```sh
   adb push ksu-frida-auth/dist/frida-auth-0.2.1.zip /sdcard/Download/
   ```

2. 打开 **KernelSU Manager → 模块 → 从本地安装**，选择该 zip。
3. 重启设备（模块包含 `sepolicy.rule` 和开机脚本，需要重启生效）。

也可以用 `ksud`：

```sh
adb push ksu-frida-auth/dist/frida-auth-0.2.1.zip /data/local/tmp/
adb shell 'su -c "ksud module install /data/local/tmp/frida-auth-0.2.1.zip"'
```

## 使用

### WebUI

1. 打开 **KernelSU Manager → 模块 → Frida Auth → WebUI**
2. 勾选允许使用 frida 的 App
3. 点 **启动 Frida**（必须从这里启动，shim 才会加载）
4. PC 端正常使用：

   ```sh
   frida -U -f com.example.app
   ```

状态说明：

| 状态 | 含义 |
| --- | --- |
| `enforced: yes` | shim 已加载，白名单生效 |
| `enforced: NO (restart via module)` | frida-server 从别处启动，授权未生效，点“启动 Frida”重开 |

### 命令行

```sh
BIN=/data/adb/modules/frida-auth/bin/frida-auth

su -c "$BIN status"                 # 查看状态
su -c "$BIN list"                   # 查看白名单
su -c "$BIN set com.foo 10554"      # 授权（包名 + UID）
su -c "$BIN del com.foo"            # 取消授权
su -c "$BIN start"                  # 用 shim 启动 frida-server
su -c "$BIN stop"                   # 停止 frida-server
su -c "$BIN path /data/local/tmp/frida-server-17.26.2-android-arm64"
su -c "$BIN autostart on"           # 开机自动启动
```

白名单文件：`/data/adb/frida-auth/allow.list`，每行 `UID 包名`：

```
10554 com.svpteam.svp
```

`service.sh` 会在开机后重新解析包名对应的 UID，并丢弃已卸载的 App。

## 与 frida-companion 配合

本项目的 `test.py` 已改为调用 `run_frida_server_with_auth()`：检测到 `frida-auth`
模块时，会自动通过 `frida-auth start` 带上 shim 启动，并校验 `ld_preload` / `shim_loaded`
状态；未安装模块时回退到原来的启动流程。

如果不是通过 `test.py` 启动，需要手动让 server 带上 shim，否则授权不生效。
启动命令前加：

```sh
LD_PRELOAD=/data/adb/modules/frida-auth/lib/arm64-v8a/libfrida_auth.so \
  /data/local/tmp/frida-server-<version>-android-arm64 -D
```

或者启动后在本模块 WebUI 点一次 **启动 Frida** 重新拉起。

## 安全说明与限制

- 这是一个**授权门禁/防误用**，不是不可绕过的安全边界。root 进程仍可通过其他方式
  注入；它的目标是阻止 frida 附加到未授权的 App。
- `sepolicy.rule` 保留了 frida 传输所需的最小 socket 规则（`appdomain → ksu`）。
  如果你已经手动加过这些规则，可以删除安装包里的 `sepolicy.rule`，授权逻辑不依赖它。
- 授权按 **UID** 生效：
  - 使用 `sharedUserId` 的多个 App 会一起授权
  - App 的 isolated 子进程（UID 90000+）默认不放行
- 必须通过本模块启动 frida-server（WebUI / `frida-auth start`），否则 shim 不加载。
- 模块启动 frida-server 时默认加 `-P`（禁用 frida 17 的 zymbiote preload）。
  不加的话 frida 会 patch zygote 并拦截所有 App 启动，App 可能卡在启动画面。
- `frida -U -f` 在 Android + Frida 17 上会走 zymbiote spawn：
  - 它会 patch `zygote`/`zygote64`/`usap`
  - 之后所有 App 启动都会被 frida 拦截
  - 未授权或握手不顺利的 App 就会卡在启动 logo

  所以用完 `frida -U -f <包名>` 后请执行 `python3 stop_frida.py`
  （或 `frida-auth stop`）优雅停止 server，还原 zygote 补丁；也可以直接重启设备。
  旧的 `kill -9` 不会还原补丁。
- 如果不需要早期 hook，推荐先正常打开 App，再用 attach：

  ```sh
  frida -U -n <包名>
  frida -U -p <pid>
  ```
- frida 的 `spawn` 走 zymbiote，不经过 ptrace，因此 shim 的 UID 门禁主要对
  `attach` 生效。frida-companion 的 WebUI 会在 spawn 前检查白名单；如果直接用
  `frida -f`，请确认目标已授权。
- 未在目标设备上做完整兼容性测试；不同 KernelSU/SukiSU 版本的 `sepolicy.rule`
  解析能力可能不同。

## 故障排查

```sh
# 看 shim 是否加载
su -c /data/adb/modules/frida-auth/bin/frida-auth status

# 看 shim 的拒绝日志
adb logcat -s frida-auth

# 确认 frida-server 进程与 LD_PRELOAD
adb shell 'su -c "cat /proc/$(pidof frida-server)/environ | tr \"\\0\" \"\\n\" | grep LD_PRELOAD"'
```

常见问题：

- **`enforced: NO`**：frida-server 不是本模块启动的，重新点“启动 Frida”
- **`shim: missing`**：`lib/<abi>/libfrida_auth.so` 不存在，重新执行 `build.py` 并安装
- **`frida-server not found`**：先推送 frida-server，或在 WebUI 设置里填入路径
- **已授权仍连不上**：检查 `sepolicy.rule` 是否生效（重启后），以及 `frida-auth` 日志

## 卸载

KernelSU Manager → 模块 → Frida Auth → 卸载，然后重启。

卸载脚本会停止 frida-server 并删除 `/data/adb/frida-auth` 下的白名单数据。
