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
check_update_on_start = True
# update interval in days, eg. check update if last check was 7 days ago
frida_update_interval = 7

# log file
log_file = 'companion.log'

# path to adb
adb_path = '~/Android/Sdk/platform-tools/adb'

# frida related executables. e.g. frida-server
frida_server_save_path = './frida_exe'

# cache file
# store something that can be deleted any time
cache_file = 'cache.json'

# flask related settings
host = '127.0.0.1'
port = 8000
debug = True
use_reloader = True
SECRET_KEY = '91afe849-63ab-4f3f-bab3-f204584d9581'
