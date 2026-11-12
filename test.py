import logging
from datetime import datetime

import frida

from settings import log_file, check_update_on_start, frida_update_interval
from tools.adb_common import set_adb_device_from_file
from tools.adb_tool import adb_connect_from_file
from utils.adb_helper import start_adb
from utils.cache_helper import cache
from utils.date_helper import timestamp_diff_in_days
from utils.frida_helper import check_frida_update, check_frida_server_update, run_frida_server_with_auth, \
    get_application_list

# init logger
logger = logging.getLogger()
fh = logging.FileHandler(log_file, mode='w')
formatter = logging.Formatter("%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s")
fh.setFormatter(formatter)
# set log level
logger.setLevel(logging.DEBUG)
fh.setLevel(logging.DEBUG)
# log handler
logger.addHandler(fh)

if __name__ == '__main__':

    # set_adb_device_from_file('./ADB_IP')
    set_adb_device_from_file('./ADB_IP_ace')

    print('Frida-companion ;)')

    # specify an old version, leave empty to use latest version
    # some frida version are broken, good versions: 16.0.3
    # pip install frida==16.0.3 frida-tools==12.0.4
    # see: https://github.com/frida/frida/issues/2360
    # frida_version = ""
    # frida_version = "16.0.3"
    # frida_version = "16.7.19"
    frida_version = "17.26.2"
    # frida_tools_version = "12.0.4"
    # frida_tools_version = "13.7.1"
    frida_tools_version = "14.13.1"

    print(f"manual install: pip install frida=={frida_version} frida-tools=={frida_tools_version}")

    if check_update_on_start:
        last_update_time = cache.get_frida_update_time()
        if not last_update_time or timestamp_diff_in_days(last_update_time,
                                                          datetime.now().timestamp()) > frida_update_interval:
            # check_frida_update()
            check_frida_update(frida_version=frida_version, frida_tools_version=frida_tools_version)

    start_adb()

    # check frida-server
    check_frida_server_update(frida_version=frida_version)

    # push frida-server and run (through frida-auth when the module is installed)
    run_frida_server_with_auth(frida_version=frida_version)

    # show application list
    get_application_list()

    print()
    print('=' * 64)
    print('重要提示：')
    print('frida -U -f 在 Android + Frida 17 上会走 zymbiote spawn：')
    print('  - 它会 patch zygote/zygote64/usap')
    print('  - 之后所有 App 启动都会被 frida 拦截')
    print('  - 未授权或握手不顺利的 App 就会卡在启动 logo')
    print()
    print('所以：')
    print('  1) 用完 frida -U -f <包名> 后，请执行：')
    print('       python3 stop_frida.py')
    print('     会优雅停止 frida-server 并还原 zygote 补丁')
    print('  2) 如果不需要早期 hook，推荐先打开 App，再用 attach：')
    print('       frida -U -n <包名>')
    print('       frida -U -p <pid>')
    print('=' * 64)
    print()

    print('finished !')
