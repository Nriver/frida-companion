from __main__ import socketio

from utils.frida_helper import get_device_list


@socketio.on('home_page', namespace='/')
def home_page():
    print('home page')


@socketio.on('refresh_device', namespace='/')
def refresh_device():
    print('refresh_device')
    device_list = get_device_list()
    return device_list
