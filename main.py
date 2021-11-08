from bp import create_app, socketio
from settings import host, port, use_reloader
from utils.adb_helper import start_adb

app = create_app()

if __name__ == '__main__':
    start_adb()
    socketio.run(app, host=host, port=port, use_reloader=use_reloader)
