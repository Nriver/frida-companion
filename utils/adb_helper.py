import logging
import os
import subprocess

from settings import adb_path

logger = logging.getLogger(__name__)
adb_path = os.path.abspath(os.path.expanduser(adb_path))


def get_android_architecture():
    cmd = [adb_path, 'shell', 'getprop', 'ro.product.cpu.abi']
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout.readline().decode('utf-8')
    logger.info(f'get_android_architecture() {res}')
    if 'arm64' in res:
        # eg.
        # arm64-v8a
        arch = 'arm64'
    else:
        arch = res.strip()
    return arch


def adb_push(src, dst, file_name):
    os.system(f'''{adb_path} push {os.path.abspath(src)} {dst}''')
    os.system(f'''{adb_path} shell "su -c 'chmod +x {os.path.join(dst, file_name)}'"''')
    os.system(f'''{adb_path} forward tcp:27042 tcp:27042''')
    os.system(f'''{adb_path} forward tcp:27043 tcp:27043''')
    # os.system(f'''{adb_path} shell "su -c '{os.path.join(dst, file_name)} &'"''')
    # os.system will hang on this execution, so use subprocess here
    subprocess.Popen([adb_path, 'shell', f"su -c '{os.path.join(dst, file_name)} &'"])
    logger.info('frida-server started')
