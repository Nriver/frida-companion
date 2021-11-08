from bp import create_app, socketio
from settings import host, port, use_reloader

app = create_app()

if __name__ == '__main__':
    socketio.run(app, host=host, port=port, use_reloader=use_reloader)
