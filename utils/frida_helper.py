import logging
import os

import frida
from tabulate import tabulate

from settings import frida_server_save_path, DEBUG
from utils.adb_helper import get_android_architecture, adb_push_and_run_frida_server
from utils.github_helper import get_latest_repo_release
from utils.requests_helper import requests_get_download

logger = logging.getLogger(__name__)


def get_latest_frida():
    return get_latest_repo_release('frida/frida')


def check_frida_update():
    """compare current installed frida and latest one"""
    logger.info('check update')
    latest_ver = get_latest_frida()
    current_ver = frida.__version__
    logger.info(f'Your frida is {current_ver}, latest frida is {latest_ver}')
    if latest_ver != current_ver:
        print(f'update detected, please update with command:')
        print('python3 -m pip install frida frida-tools -U --user')
        exit()
    logger.info('Good to go')


def get_frida_server(frida_version, device_arch):
    """download frida-server"""
    frida_server_file = f'frida-server-{frida_version}-android-{device_arch}'
    xz_file = frida_server_file + '.xz'
    url = f'https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{device_arch}.xz'
    logger.info(f'Download url {url}')
    requests_get_download(url, os.path.join(frida_server_save_path, xz_file))
    # decompress xz file
    os.system(f'xz -d {os.path.join(frida_server_save_path, xz_file)}')


def check_frida_server_update(force_update=False):
    """check and get latest frida-server"""
    device_arch = get_android_architecture()
    frida_version = frida.__version__
    frida_server_file = f'frida-server-{frida_version}-android-{device_arch}'
    if not force_update and os.path.exists(os.path.join(frida_server_save_path, frida_server_file)):
        return

    if not os.path.exists(frida_server_save_path):
        os.makedirs(frida_server_save_path)
    get_frida_server(frida_version, device_arch)


def run_frida_server(target_path='/data/local/tmp/'):
    """run frida-server"""
    device_arch = get_android_architecture()
    frida_version = frida.__version__
    frida_server_file = f'frida-server-{frida_version}-android-{device_arch}'
    adb_push_and_run_frida_server(os.path.join(frida_server_save_path, frida_server_file), target_path,
                                  frida_server_file)


def get_application_list():
    """application list"""
    device_args = {}
    device_manager = frida.get_device_manager()
    device = device_manager.get_usb_device(**device_args)
    applications = device.enumerate_applications()
    apps = []
    for x in applications:
        row = x.name, x.identifier
        apps.append(row)
    if DEBUG:
        table_data = tabulate(apps, headers=['App name', 'Identifier'], showindex="always", tablefmt="fancy_grid")
        print(table_data)
        logger.debug('application list:\n' + table_data)
    return apps
