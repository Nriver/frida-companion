from __main__ import socketio


@socketio.on('home_page', namespace='/')
def home_page():
    print('home page')
