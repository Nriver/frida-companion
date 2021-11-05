import logging

import frida

from utils.github_helper import get_latest_repo_release

logger = logging.getLogger(__name__)


def get_latest_frida():
    return get_latest_repo_release('frida/frida')


def check_frida_update():
    logger.info('check update')
    latest_ver = get_latest_frida()
    current_ver = frida.__version__
    logger.info(f'Your frida is {current_ver}, latest frida is {latest_ver}')
    if latest_ver != current_ver:
        print(f'update detected, please update with command:')
        print('python3 -m pip install frida frida-tools -U --user')
        exit()
    logger.info('Good to go')
