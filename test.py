import logging
from datetime import datetime

import frida

from settings import log_file, check_update_on_start, frida_update_interval
from utils.adb_helper import start_adb
from utils.cache_helper import cache
from utils.date_helper import timestamp_diff_in_days
from utils.frida_helper import check_frida_update, check_frida_server_update, run_frida_server, get_application_list

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
    print('Frida-companion ;)')

    if check_update_on_start:
        last_update_time = cache.get_frida_update_time()
        if not last_update_time or timestamp_diff_in_days(last_update_time,
                                                          datetime.now().timestamp()) > frida_update_interval:
            check_frida_update()

    start_adb()
    logger.info(frida.get_usb_device())

    # check frida-server
    check_frida_server_update()

    # push frida-server and run
    run_frida_server()

    # show application list
    get_application_list()

    print('finished !')
