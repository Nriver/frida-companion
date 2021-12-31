import logging
import os
import subprocess

from settings import adb_path

logger = logging.getLogger(__name__)
adb_path = os.path.abspath(os.path.expanduser(adb_path))


def start_adb(device_id=None):
    """try to start adb"""
    if device_id:
        cmd = [adb_path, '-s', device_id, 'shell', 'echo hello']
    else:
        cmd = [adb_path, 'shell', 'echo hello']
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    return res.stdout.read().decode('utf-8').strip()


def is_android(device_id):
    if 'hello' in start_adb(device_id):
        return True
    return False


def is_frida_server_running(device_id):
    cmd = [adb_path, '-s', device_id, 'shell', 'ps|grep frida-server']
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    if 'frida-server' in res.stdout.read().decode('utf-8').strip():
        return True
    return False


def stop_frida_server(device_id):
    cmd = [adb_path, '-s', device_id, 'shell', 'ps|grep frida']
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = res.stdout.read().decode('utf-8').strip()
    print(output)
    if output:
        for x in output.split('\n'):
            pid = x.split()[1]
            cmd = [adb_path, '-s', device_id, 'shell', f'''"su -c 'kill {pid}'"''']
            subprocess.Popen(cmd, stdout=subprocess.PIPE)
        print('frida-server stopped')
    return


def get_android_architecture(device_id=None):
    if device_id:
        cmd = [adb_path, '-s', device_id, 'shell', 'getprop', 'ro.product.cpu.abi']
    else:
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


def adb_push_and_run_frida_server(src, dst, file_name, device_id=None):
    if device_id:
        device_switch = f'-s {device_id}'
    else:
        device_switch = ''

    os.system(f'''{adb_path} {device_switch} push {os.path.abspath(src)} {dst}''')
    os.system(f'''{adb_path} {device_switch} shell "su -c 'chmod +x {os.path.join(dst, file_name)}'"''')
    os.system(f'''{adb_path} {device_switch} forward tcp:27042 tcp:27042''')
    os.system(f'''{adb_path} {device_switch} forward tcp:27043 tcp:27043''')
    # os.system(f'''{adb_path} shell "su -c '{os.path.join(dst, file_name)} &'"''')
    # os.system will hang on this execution, so use subprocess here
    if device_id:
        subprocess.Popen([adb_path, '-s', device_id, 'shell', f"su -c '{os.path.join(dst, file_name)} &'"])
    else:
        subprocess.Popen([adb_path, 'shell', f"su -c '{os.path.join(dst, file_name)} &'"])
    logger.info('frida-server started')


def force_stop_application_by_identifier(identifier, device_id):
    # kill application by identifier name e.g. com.xyx.abc
    subprocess.run([adb_path, '-s', device_id, 'shell', f'am force-stop {identifier}'])


def force_restart_application_by_identifier(identifier, device_id):
    # force restart application by identifier name e.g. com.xyx.abc
    subprocess.run([adb_path, '-s', device_id, 'shell', f'am force-stop {identifier} && monkey -p {identifier} 1'])


def get_package_list():
    """package list"""
    package_list = []
    res = subprocess.Popen([adb_path, 'shell', 'pm', 'list', 'package'], stdout=subprocess.PIPE)
    for line in res.stdout.read().decode('utf-8').split('\n'):
        if not 'package:' in line:
            continue
        package_name = line.split('package:')[1].strip()
        package_list.append(package_name)
    return package_list


def is_package_installed(package_name):
    """check package exists"""
    return package_name in get_package_list()
