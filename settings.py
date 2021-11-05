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

log_file = 'companion.log'
