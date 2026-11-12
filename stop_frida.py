#!/usr/bin/env python3
"""Stop frida-server gracefully on an Android device.

`frida -U -f` 在 Android + Frida 17 上会走 zymbiote spawn：

- 它会 patch zygote/zygote64/usap
- 之后所有 App 启动都会被 frida 拦截
- 未授权或握手不顺利的 App 就会卡在启动 logo

Sending SIGTERM lets frida-server run its shutdown path and revert those
patches. This script uses the frida-auth module when available, otherwise it
falls back to TERM/KILL.

如果不需要早期 hook，推荐先正常打开 App，再用 attach：
    frida -U -n <包名>
    frida -U -p <pid>
"""

from tools.adb_common import execute_with_root, set_adb_device_from_file
from utils.adb_helper import is_frida_auth_installed, is_frida_server_running, \
    stop_frida_server_gracefully


def main():
    # Keep the same device selection as test.py.
    set_adb_device_from_file('./ADB_IP_ace')

    if not is_frida_server_running():
        print('[INFO] frida-server 没有运行')
    else:
        print('[INFO] 停止 frida-server（SIGTERM，会还原 zygote 补丁）...')
        stop_frida_server_gracefully()

        if is_frida_server_running():
            print('[警告] frida-server 仍在运行，请检查设备或手动重启')
        else:
            print('[OK] frida-server 已停止')
            print('     如果之前用过 frida -U -f，zygote 补丁会在优雅退出时还原；')
            print('     若仍有 App 卡启动，重启一次手机最稳妥。')

            if is_frida_auth_installed():
                status = execute_with_root('/data/adb/modules/frida-auth/bin/frida-auth status')
                if status:
                    print('[frida-auth] status:')
                    print(status)


if __name__ == '__main__':
    main()
