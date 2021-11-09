from bp import create_app, socketio
from settings import host, port, use_reloader
from utils.adb_helper import start_adb
from utils.cache_helper import cache

app = create_app()


@app.context_processor
def inject_cache():
    """make cache accessible in sessions, make template render easier"""
    return dict(cache=cache)


if __name__ == '__main__':
    start_adb()
    socketio.run(app, host=host, port=port, use_reloader=use_reloader)
