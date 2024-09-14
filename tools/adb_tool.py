import os


def adb_connect_from_file(file_path='./ADB_IP'):
    try:
        # 读取文件内容
        with open(file_path, 'r') as file:
            ip_address = file.read().strip()

        if not ip_address:
            raise ValueError("文件为空或未找到有效的IP地址")

        # 构建adb命令
        adb_command = f"adb connect {ip_address}"

        # 执行adb命令
        result = os.system(adb_command)

        if result == 0:
            print(f"成功连接到 {ip_address}")
        else:
            print(f"连接失败: {ip_address}")

    except FileNotFoundError:
        print(f"未找到文件: {file_path}")
    except Exception as e:
        print(f"发生错误: {e}")

    return
