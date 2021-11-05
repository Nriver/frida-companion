import logging

import frida

from settings import log_file, check_update_on_start
from utils.frida_helper import check_frida_update, check_frida_server_update, run_frida_server

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
        check_frida_update()
    logger.info(frida.get_usb_device())

    # check frida-server
    check_frida_server_update(force_update=True)

    # push frida-server and run
    run_frida_server()
    print('finished !')
