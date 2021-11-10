import logging
import os
import platform
from datetime import datetime
from shutil import copyfile

import frida
from tabulate import tabulate

from settings import frida_server_save_path, DEBUG, device_type_order
from utils.adb_helper import get_android_architecture, adb_push_and_run_frida_server, is_android, \
    is_frida_server_running
from utils.github_helper import get_latest_repo_release
from utils.requests_helper import requests_get_download

logger = logging.getLogger(__name__)


def get_latest_frida():
    return get_latest_repo_release('frida/frida')


def check_frida_update():
    """compare current installed frida and latest one"""
    from utils.cache_helper import cache
    logger.info('check update')
    latest_ver = get_latest_frida()
    current_ver = frida.__version__
    logger.info(f'Your frida is {current_ver}, latest frida is {latest_ver}')
    if latest_ver != current_ver:
        print(f'update detected, please update with command:')
        print('python3 -m pip install frida frida-tools -U --user')
        exit()

    cache.set_frida_update_time(datetime.now().timestamp())
    logger.info('Good to go')


def get_frida_server(frida_version, device_arch):
    """download frida-server"""
    if not os.path.exists(frida_server_save_path):
        os.makedirs(frida_server_save_path)

    frida_file = f'frida-server-{frida_version}-android-{device_arch}'
    xz_file = frida_file + '.xz'
    url = f'https://github.com/frida/frida/releases/download/{frida_version}/{xz_file}'
    local_frida_file = os.path.join(frida_server_save_path, frida_file)
    local_xz_file = os.path.join(frida_server_save_path, xz_file)
    print(local_xz_file)
    if os.path.exists(local_frida_file):
        logger.info(f'skip download')
    else:
        logger.info(f'Download frida server {url}')
        requests_get_download(url, local_xz_file)
        # decompress xz file
        os.system(f'xz -d {local_xz_file}')


def get_frida_gadget(frida_version, device_arch):
    # download frida gadget
    frida_gadget_save_path = os.path.expanduser('~/.cache/frida/')
    if not os.path.exists(frida_gadget_save_path):
        os.makedirs(frida_gadget_save_path)

    frida_file = f'frida-gadget-{frida_version}-android-{device_arch}.so'
    xz_file = frida_file + '.xz'
    url = f'https://github.com/frida/frida/releases/download/{frida_version}/{xz_file}'
    print('download', url)
    local_frida_file = os.path.join(frida_gadget_save_path, frida_file)
    local_xz_file = os.path.join(frida_gadget_save_path, xz_file)
    print(local_xz_file)
    if os.path.exists(local_frida_file):
        logger.info(f'skip download')
    else:
        logger.info(f'Download frida gadget {url}')
        requests_get_download(url, local_xz_file)
        # decompress xz file
        os.system(f'xz -d {local_xz_file}')

        # need to be a default name which frida can recognize
        so_path = os.path.join(frida_gadget_save_path, f'gadget-android-{device_arch}.so')
        if os.path.exists(so_path):
            os.remove(so_path)
        copyfile(local_frida_file, so_path)


def get_all_frida_gadget_for_android(frida_version):
    for device_arch in ['arm', 'arm64', 'x86', 'x86_64']:
        get_frida_gadget(frida_version, device_arch)


def check_frida_server_update():
    """check and get latest frida-server"""
    device_arch = get_android_architecture()
    frida_version = frida.__version__

    get_frida_server(frida_version, device_arch)
    get_frida_gadget(frida_version, device_arch)


def run_frida_server(device_id=None, target_path='/data/local/tmp/'):
    """run frida-server"""
    device_arch = get_android_architecture(device_id)
    frida_version = frida.__version__
    frida_server_file = f'frida-server-{frida_version}-android-{device_arch}'
    adb_push_and_run_frida_server(os.path.join(frida_server_save_path, frida_server_file), target_path,
                                  frida_server_file, device_id)


def get_device_list():
    """list adb devices"""

    # https://github.com/frida/frida-python/issues/189
    # frida does not recognize hot-plug usb device unless whole library is reloaded, may be a bug in frida?
    import importlib
    importlib.reload(frida)

    devices = frida.enumerate_devices()
    print(devices)
    device_list = []
    for x in devices:
        # check if remote device is available
        # usually a remote device is set as a port forward with `adb forward tcp:27042 tcp:27042`
        if x.type == 'remote':
            try:
                x.enumerate_processes()
            except Exception as e:
                print('ignore unavailable remote device')
                continue
        device_list.append({'name': x.name, 'type': x.type, 'id': x.id, 'system': get_device_system(x.id)})
    # sort
    # usb device first
    device_list = sorted(device_list, key=lambda x: device_type_order.index(x['type']))
    return device_list


def get_device(device_id):
    return frida.get_device(id=device_id)


def get_device_type(device_id):
    return frida.get_device(id=device_id).type


def get_application_list(device_id=None):
    """application list"""
    if device_id:
        device = get_device(device_id)
    else:
        device_args = {}
        device_manager = frida.get_device_manager()
        device = device_manager.get_usb_device(**device_args)

    apps = []
    if device.type == 'local':
        applications = device.enumerate_processes()
        for x in applications:
            row = {
                'name': x.name,
                'identifier': x.pid
            }
            apps.append(row)
        # sort by name
        apps = sorted(apps, key=lambda x: x['name'])
    else:
        # frida-server must be running before we use enumerate_process
        # if frida-server is not running enumerate_process will wait until timeout which is too slow

        if is_android(device_id):
            # if is_frida_server_running(device_id):
            #     stop_frida_server(device_id)
            # run_frida_server(device_id)
            if not is_frida_server_running(device_id):
                run_frida_server(device_id)

        applications = device.enumerate_applications()
        for x in applications:
            row = {
                'name': x.name,
                'identifier': x.identifier
            }
            apps.append(row)
        # sort by identifier
        apps = sorted(apps, key=lambda x: x['identifier'])
        if DEBUG:
            table_data = tabulate([[x['name'], x['identifier']] for x in apps], headers=['App name', 'Identifier'],
                                  showindex="always", tablefmt="fancy_grid")
            print(table_data)
            logger.debug('application list:\n' + table_data)
    return apps


def get_device_system(device_id):
    """get device os system type"""
    # device = frida.get_device(device_id)
    device_type = get_device_type(device_id)
    if device_type == 'usb':
        # use a quick check with adb
        if is_android(device_id):
            return 'android'
        else:
            return 'ios'
    elif device_type == 'local':
        return platform.system()
    elif device_type == 'remote':
        return 'unknown'
    return None
