import logging
import os
import subprocess
import time

from settings import adb_path
from tools.adb_common import run_adb_command, set_adb_device_from_file, execute_with_root

logger = logging.getLogger(__name__)
adb_path = os.path.abspath(os.path.expanduser(adb_path))

FRIDA_AUTH_BIN = '/data/adb/modules/frida-auth/bin/frida-auth'
FRIDA_AUTH_ALLOWLIST = '/data/adb/frida-auth/allow.list'


def start_adb(device_id=None):
    """try to start adb"""
    cmd = ['shell', 'echo', 'hello']
    return run_adb_command(cmd, device_id=device_id)


def is_android(device_id=None):
    if 'hello' in start_adb(device_id=device_id):
        return True
    return False


def is_frida_server_running(device_id=None):
    cmd = ['shell', "ps -A -o ARGS 2>/dev/null | grep '[f]rida-server' || true"]
    res = run_adb_command(cmd, device_id=device_id)
    return 'frida-server' in (res or '')


def stop_frida_server_gracefully(device_id=None):
    """Stop frida-server with SIGTERM first so it can revert zygote patches.

    When the frida-auth module is active, use its stop command so the crash
    reporter child is cleaned up as well.
    """
    if is_frida_auth_installed(device_id):
        res = execute_with_root(f'{FRIDA_AUTH_BIN} stop', device_id=device_id)
        logger.info(f'frida-auth stop: {res}')
        return res

    execute_with_root('pkill -TERM -f frida-server', device_id=device_id)
    time.sleep(1.5)
    execute_with_root('pkill -KILL -f frida-server', device_id=device_id)
    execute_with_root('pkill -KILL -f frida-helper', device_id=device_id)
    return None


def stop_frida_server(device_id):
    stop_frida_server_gracefully(device_id)
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


def is_frida_auth_installed(device_id=None):
    """Check whether the frida-auth KernelSU module is active on the device."""
    res = execute_with_root(f'test -x {FRIDA_AUTH_BIN} && echo yes', device_id=device_id)
    return 'yes' in (res or '')


def get_frida_auth_allowlist(device_id=None):
    """Return a list of (uid, package) entries from the frida-auth allowlist."""
    res = execute_with_root(f'cat {FRIDA_AUTH_ALLOWLIST}', device_id=device_id)
    entries = []
    for line in (res or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1]))
    return entries


def get_package_uid(package_name, device_id=None):
    """Resolve the UID of an installed package, or None."""
    res = run_adb_command(['shell', 'cmd', 'package', 'list', 'packages', '-U'], device_id=device_id)
    if not res:
        res = run_adb_command(['shell', 'pm', 'list', 'packages', '-U'], device_id=device_id)
    for line in (res or '').splitlines():
        parts = line.split()
        if not parts or parts[0] != f'package:{package_name}':
            continue
        for part in parts[1:]:
            if part.startswith('uid:'):
                return part[4:]
    return None


def is_app_authorized(package_name, device_id=None):
    """Check the frida-auth allowlist for a package.

    Returns True when the module is not installed, preserving legacy behaviour.
    """
    if not is_frida_auth_installed(device_id):
        return True

    allow = get_frida_auth_allowlist(device_id)
    for uid, pkg in allow:
        if pkg == package_name:
            return True

    uid = get_package_uid(package_name, device_id=device_id)
    if uid is None:
        return False
    return any(entry_uid == uid for entry_uid, _ in allow)


def push_frida_server(src, dst='/data/local/tmp/', file_name=None, device_id=None):
    """Stop old frida processes, push the server and set up port forwards."""
    # Stop the old server gracefully so it can revert zygote patches.
    stop_frida_server_gracefully(device_id)

    # push new file
    run_adb_command(f'''push {os.path.abspath(src)} {dst}''', device_id=device_id)
    server_path = os.path.join(dst, file_name)
    execute_with_root(f'''chmod 777 {server_path}''', device_id=device_id)

    # port forward
    run_adb_command(f'''forward tcp:27042 tcp:27042''', device_id=device_id)
    run_adb_command(f'''forward tcp:27043 tcp:27043''', device_id=device_id)

    return server_path


def start_frida_server_with_auth(server_path, device_id=None):
    """Start frida-server through the frida-auth module and return its status."""
    execute_with_root(f'{FRIDA_AUTH_BIN} path {server_path}', device_id=device_id)
    execute_with_root(f'{FRIDA_AUTH_BIN} start', device_id=device_id)
    status = execute_with_root(f'{FRIDA_AUTH_BIN} status', device_id=device_id)
    logger.info(f'frida-auth status:\n{status}')
    return status


def adb_push_and_run_frida_server(src, dst, file_name, device_id=None):

    server_path = push_frida_server(src, dst, file_name, device_id)

    if is_frida_auth_installed(device_id):
        status = start_frida_server_with_auth(server_path, device_id)
        print('[frida-auth] status:\n' + (status or '<no output>'))
        if 'shim_loaded=yes' not in (status or ''):
            logger.warning('frida-auth shim was not loaded, authorization is disabled; starting directly')
            res = execute_with_root(f'{server_path} -P', device_id=device_id, nohup=True, return_pid=True)
            logger.info(f'frida-server started, pid is {res}')
    else:
        # os.system will hang on this execution, so use subprocess here
        res = execute_with_root(f'{server_path} -P', device_id=device_id, nohup=True, return_pid=True)
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
    cmd = ['shell', f'mkdir {tmp_directory} && cp -r {android_path}/* {tmp_directory};']
    res = execute_with_root(cmd, device_id=device_id)
    if res:
        print(res)
        # delete if already exist
        if 'File exists' in res.stderr:
            cmd = ['shell', f"""rm -r {tmp_directory}"""]
            run_adb_command(cmd, device_id=device_id)
            cmd = ['shell', f"""su -c 'mkdir {tmp_directory} && cp -r {android_path}/* {tmp_directory};'"""]
            res = run_adb_command(cmd, device_id=device_id)
        # target is a file
        if 'Not a directory' in res.stderr:
            cmd =['shell', f"""su -c 'cp {android_path} {tmp_directory};'"""]
            res = run_adb_command(cmd, device_id=device_id)

    cmd = ['pull', tmp_directory, output_directory]
    res = run_adb_command(cmd, device_id=device_id)

    print(res)
    cmd = ['shell', f"rm -r {tmp_directory}"]
    res = run_adb_command(cmd, device_id=device_id)


if __name__ == '__main__':
    set_adb_device_from_file('../ADB_IP_ace')
    start_adb()
    print(is_frida_server_running())
    # extract_files('/data/user/0/mark.via', './tmp')
