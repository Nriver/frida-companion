DEBUG = True

# proxy for requests
# USE_PROXY = False
USE_PROXY = True
PROXIES = {
    "http": "http://127.0.0.1:10809",
    "https": "http://127.0.0.1:10809"
}

# frida-server version override
frida_server_version = ''

# check frida update on startup
check_update_on_start = False

# log file
log_file = 'companion.log'

# path to adb
adb_path = '~/Android/Sdk/platform-tools/adb'

# frida related executables. e.g. frida-server
frida_server_save_path = './frida_exe'
