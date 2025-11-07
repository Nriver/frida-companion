import logging
import os
import subprocess

from settings import adb_path
from tools.adb_common import run_adb_command, set_adb_device_from_file, execute_with_root

logger = logging.getLogger(__name__)
adb_path = os.path.abspath(os.path.expanduser(adb_path))


def start_adb(device_id=None):
    """try to start adb"""
    cmd = ['shell', 'echo', 'hello']
    return run_adb_command(cmd, device_id=device_id)


def is_android(device_id=None):
    if 'hello' in start_adb(device_id=device_id):
        return True
    return False


def is_frida_server_running(device_id=None):
    cmd = ['shell', 'ps|grep frida-server']
    res = run_adb_command(cmd, device_id=device_id)
    if 'frida-server' in res.strip():
        return True
    return False


def stop_frida_server(device_id):
    cmd = ['shell', 'ps|grep frida']
    res = run_adb_command(cmd, device_id=device_id)
    print(res)
    if res:
        for x in res.split('\n'):
            pid = x.split()[1]
            cmd = [adb_path, '-s', device_id, 'shell', f'''"su -c 'kill {pid}'"''']
            subprocess.Popen(cmd, stdout=subprocess.PIPE)
        print('frida-server stopped')
    return


def get_android_architecture(device_id=None):
    cmd = ['shell', 'getprop', 'ro.product.cpu.abi']
    res = run_adb_command(cmd, device_id=device_id)
    logger.info(f'get_android_architecture() {res}')
    if 'arm64' in res:
        # eg.
        # arm64-v8a
        arch = 'arm64'
    else:
        arch = res.strip()
    return arch


def adb_push_and_run_frida_server(src, dst, file_name, device_id=None):

    # kill old frida process
    execute_with_root(['shell', 'pkill -9 frida'], device_id=device_id)

    # push new file
    run_adb_command(f'''push {os.path.abspath(src)} {dst}''', device_id=device_id)
    execute_with_root(f'''chmod 777 {os.path.join(dst, file_name)}''', device_id=device_id)

    # port forward
    run_adb_command(f'''forward tcp:27042 tcp:27042''', device_id=device_id)
    run_adb_command(f'''forward tcp:27043 tcp:27043''', device_id=device_id)

    # os.system will hang on this execution, so use subprocess here
    cmd = f"{os.path.join(dst, file_name)}"
    res = execute_with_root(cmd, device_id=device_id, nohup=True, return_pid=True)
    logger.info(f'frida-server started, pid is {res}')
    print('ok')


def force_stop_application_by_identifier(identifier, device_id=None):
    # kill application by identifier name e.g. com.xyx.abc
    cmd = ['shell', f'am force-stop {identifier}']
    run_adb_command(cmd, device_id=device_id)

def force_restart_application_by_identifier(identifier, device_id=None):
    # force restart application by identifier name e.g. com.xyx.abc
    cmd = ['shell', f'am force-stop {identifier} && monkey -p {identifier} 1']
    run_adb_command(cmd, device_id=device_id)


def get_package_list(device_id=None):
    """package list"""
    package_list = []
    cmd = ['shell', 'pm', 'list', 'package']
    res = run_adb_command(cmd, device_id=device_id)
    for line in res.split('\n'):
        if not 'package:' in line:
            continue
        package_name = line.split('package:')[1].strip()
        package_list.append(package_name)
    return package_list


def is_package_installed(package_name, device_id=None):
    """check package exists"""
    return package_name in get_package_list(device_id=device_id)


def extract_files(android_path, output_directory, tmp_directory='/sdcard/_adb_cache', device_id=None):
    """
    extract android files
    copy files to a temporary folder in sdcard then pull it with adb and clean up
    """
    cmd = ['shell', 'mkdir {tmp_directory} && cp -r {android_path}/* {tmp_directory};']
    res = execute_with_root(cmd, device_id=device_id)
    if res:
        print(res)
        # delete if already exist
        if 'File exists' in res.stderr:
            cmd = ['shell', f"""rm -r {tmp_directory}"""]
            res = run_adb_command(cmd, device_id=device_id)
            cmd = ['shell', f"""su -c 'mkdir {tmp_directory} && cp -r {android_path}/* {tmp_directory};'"""]
            res = run_adb_command(cmd, device_id=device_id)
        # target is a file
        if 'Not a directory' in res.stderr:
            res = subprocess.run([adb_path, 'shell', f"""su -c 'cp {android_path} {tmp_directory};'"""],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")

    res = subprocess.run([adb_path, 'pull', tmp_directory, output_directory], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, encoding="utf-8")
    print(res.stdout)
    subprocess.run([adb_path, 'shell', f"rm -r {tmp_directory}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   encoding="utf-8")


if __name__ == '__main__':
    set_adb_device_from_file('../ADB_IP_ace')
    start_adb()
    print(is_frida_server_running())
    # extract_files('/data/user/0/mark.via', './tmp')
