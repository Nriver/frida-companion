import os
import subprocess
import time


def check_and_restart_adb():
    """检测adb服务是否响应，若不响应则重启adb服务"""
    try:
        # 使用 subprocess 捕获输出和返回码，方便判断
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)

        output = result.stdout.decode('utf-8')
        err = result.stderr.decode('utf-8')

        # adb正常时，输出一般包含 "List of devices attached"
        if result.returncode != 0 or "List of devices attached" not in output:
            print("检测到adb服务异常，准备重启...")
            restart_adb_service()
        else:
            print("adb服务正常")
    except Exception as e:
        print(f"检测adb服务异常: {e}")
        print("准备重启adb服务...")
        restart_adb_service()


def restart_adb_service():
    """重启adb服务"""
    print("停止adb服务...")
    os.system("adb kill-server")
    time.sleep(1)
    print("启动adb服务...")
    os.system("adb start-server")
    time.sleep(2)
    print("adb服务已重启")


def get_adb_devices():
    """
    获取adb devices的输出并解析结果，返回设备列表
    返回格式示例：
    [
        {"serial": "emulator-5554", "status": "device"},
        {"serial": "192.168.0.101:5555", "status": "offline"},
        ...
    ]
    """
    try:
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        output = result.stdout.decode('utf-8')
        if result.returncode != 0:
            print(f"adb devices 执行失败: {result.stderr.decode('utf-8')}")
            return []

        lines = output.strip().split('\n')
        devices = []

        # adb devices 输出第一行是 "List of devices attached"
        # 设备信息从第二行开始
        for line in lines[1:]:
            line = line.strip()
            if line == '':
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                devices.append({"serial": serial, "status": status})

        return devices
    except Exception as e:
        print(f"获取adb设备列表异常: {e}")
        return []


def adb_connect_from_file(file_path='./ADB_IP', wait_time=1, disconnect_before_connect=False):
    """连接成功则返回adb连接的ip信息"""

    if disconnect_before_connect:
        print("先断开所有adb连接")
        adb_disconnect_all()

    try:
        # 读取文件内容
        with open(file_path, 'r') as file:
            ip_address = file.read().strip()

        if not ip_address:
            raise ValueError("文件为空或未找到有效的IP地址")

        if ip_address.upper() == 'SKIP':
            print("检测到 特殊关键字 SKIP，跳过adb连接")
            return None  # 跳过连接也返回 None

        # 构建adb命令
        adb_command = f"adb connect {ip_address}"

        # 执行adb命令
        result = os.system(adb_command)

        time.sleep(wait_time)

        if result == 0:
            print(f"成功连接到 {ip_address}")
            return ip_address
        else:
            print(f"连接失败: {ip_address}")
            return None

    except FileNotFoundError:
        print(f"未找到文件: {file_path}")
    except Exception as e:
        print(f"发生错误: {e}")

    return None


def adb_disconnect_all():
    """断开所有adb连接"""
    os.system("adb disconnect")
    time.sleep(3)


def adb_disconnect_device(device_ip_or_serial):
    """断开指定设备的 adb 连接"""
    if not device_ip_or_serial:
        print("设备地址为空，无法断开连接")
        return

    cmd = f"adb disconnect {device_ip_or_serial}"
    print(f"断开设备连接: {device_ip_or_serial}")
    result = os.system(cmd)
    if result == 0:
        print(f"成功断开 {device_ip_or_serial}")
    else:
        print(f"断开 {device_ip_or_serial} 失败")


def adb_disconnect_from_file(file_path='./ADB_IP_ace'):
    """从文件读取设备地址并断开对应adb连接"""
    try:
        with open(file_path, 'r') as file:
            device_ip_or_serial = file.read().strip()

        if not device_ip_or_serial:
            raise ValueError("文件为空或未找到有效的设备地址")

        if device_ip_or_serial.upper() == 'SKIP':
            print("检测到特殊关键字 SKIP，跳过断开操作")
            return

        adb_disconnect_device(device_ip_or_serial)

    except FileNotFoundError:
        print(f"未找到文件: {file_path}")
    except Exception as e:
        print(f"发生错误: {e}")


if __name__ == "__main__":
    check_and_restart_adb()
    print(get_adb_devices())
    adb_connect_from_file("../ADB_IP")
