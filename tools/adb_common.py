import os
import subprocess


def set_adb_device_from_file(filepath):
    """
    从文件中读取设备 IP，并设置环境变量 ADB_DEVICE_SERIAL。
    """
    with open(filepath, 'r') as f:
        ip = f.read().strip()
        if ip:
            os.environ['ADB_DEVICE_SERIAL'] = ip
            print(f"[INFO] adb使用设备: {ip}")


def connect_adb_device():
    """
    尝试连接 ADB_DEVICE_SERIAL 指定的设备（仅当其为 IP:端口 格式）。
    如果连接成功，打印连接信息。
    如果连接失败，提示错误信息。
    """
    device_ip = os.environ.get("ADB_DEVICE_SERIAL")
    if not device_ip:
        print("[错误] 未设置 ADB_DEVICE_SERIAL 环境变量。")
        return None

    if ':' not in device_ip:
        print(f"[跳过] 当前设备 '{device_ip}' 不是 IP 形式，不需要 adb connect。")
        return device_ip

    print(f"[信息] 正在尝试连接设备: {device_ip} ...")
    result = subprocess.run(["adb", "connect", device_ip],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True)

    output = result.stdout.strip() or result.stderr.strip()
    print(f"[ADB] {output}")

    if "connected to" in output.lower() or "already connected" in output.lower():
        return device_ip
    else:
        print(f"[错误] 无法连接到设备 '{device_ip}'。")
        return None


def run_adb_command(command, device_id=None, retry=True, use_root=False, nohup=False, return_pid=False):
    """
    执行 adb 命令，支持字符串或列表格式。
    如果设备未连接，自动尝试 adb connect 并重试一次。
    - use_root=True时，命令通过 su -c 执行（root权限）。
    - nohup=True：后台运行并立即返回
    - return_pid=True：返回启动进程的 PID（仅当 nohup=True 时有效）
    成功返回命令输出字符串，失败返回 None。
    """
    if isinstance(command, str):
        cmd_str = command.strip()
        cmd_list = cmd_str.split()
    elif isinstance(command, list):
        cmd_list = command
        cmd_str = " ".join(command)
    else:
        raise TypeError("命令必须是字符串或列表类型")

    device = device_id or os.environ.get("ADB_DEVICE_SERIAL")
    base_cmd = ["adb"]
    if device:
        base_cmd += ["-s", device]

    if use_root:
        # adb shell su -c ...
        if cmd_list[0] == "shell":
            inner_cmd = " ".join(cmd_list[1:])
        else:
            inner_cmd = cmd_str

        # >>> 关键改动：支持 nohup 与返回 PID <<<
        if nohup:
            if return_pid:
                inner_cmd = f"nohup {inner_cmd} >/dev/null 2>&1 & echo $!"
            else:
                inner_cmd = f"nohup {inner_cmd} >/dev/null 2>&1 &"
        full_cmd = base_cmd + ["shell", "su", "-c", f"'{inner_cmd}'"]
    else:
        if nohup:
            if cmd_list[0] != "shell":
                inner_cmd = cmd_str
            else:
                inner_cmd = " ".join(cmd_list[1:])
            if return_pid:
                inner_cmd = f"nohup {inner_cmd} >/dev/null 2>&1 & echo $!"
            else:
                inner_cmd = f"nohup {inner_cmd} >/dev/null 2>&1 &"
            full_cmd = base_cmd + ["shell", inner_cmd]
        else:
            full_cmd = base_cmd + cmd_list

    print("[ADB CMD]", " ".join(full_cmd))

    result = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout.strip() or result.stderr.strip()

    if result.returncode == 0:
        return output if output else None

    # === 错误处理 ===
    if retry and device and f"device '{device}' not found" in output.lower():
        print(f"[警告] 找不到设备 '{device}'，正在尝试连接...")
        if ':' in device:
            connect_result = subprocess.run(["adb", "connect", device], stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True)
            print(f"[信息] adb connect 结果：{connect_result.stdout.strip() or connect_result.stderr.strip()}")
            return run_adb_command(command, retry=False, use_root=use_root,
                                   nohup=nohup, return_pid=return_pid)
    print(f"[错误] ADB执行失败: {output}")
    return None


def execute_with_root(cmd, device_id=None, nohup=False, return_pid=False):
    """
    用 root 权限执行 adb shell 命令，返回执行结果字符串或 None。
    cmd 支持字符串或列表格式（不含 adb 命令部分）。
    - nohup=True：后台运行（非阻塞）
    - return_pid=True：返回PID（仅nohup=True时）
    """
    return run_adb_command(cmd, device_id=device_id, use_root=True, nohup=nohup, return_pid=return_pid)



if __name__ == '__main__':
    set_adb_device_from_file('../ADB_IP_ace')
    execute_with_root(['shell', 'pkill -9 frida'])
    execute_with_root('/data/local/tmp/frida-server-16.6.6-android-arm64', nohup=True)

    # set_adb_device_from_file('../ADB_IP_ace')
    # result = run_adb_command('shell getprop ro.product.model')
    # print(result)
    # result = execute_with_root("getprop ro.product.model")
    # print(result)
    #
    # set_adb_device_from_file('../ADB_IP')
    # result = run_adb_command('shell getprop ro.product.model')
    # print(result)
