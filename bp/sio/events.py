from .. import socketio


@socketio.on('connected', namespace='/')
def handle_message(message):
    print('connected: ' + message['data'])
