from __main__ import socketio

from flask import render_template

from utils.frida_helper import get_device_list


@socketio.on('home_page', namespace='/')
def home_page():
    print('home page')


@socketio.on('refresh_device', namespace='/')
def refresh_device():
    print('refresh_device')
    device_list = get_device_list()

    device_list_html = render_template("components/device_list.htm", **locals())

    socketio.emit('refresh_device_response',
                  {'data': {'device_list_html': device_list_html}})
    return device_list
