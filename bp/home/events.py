from __main__ import socketio

from flask import render_template

from utils.cache_helper import cache
from utils.frida_helper import get_device_list, get_application_list


@socketio.on('home_page', namespace='/')
def home_page():
    print('home page')


@socketio.on('refresh_device', namespace='/')
def refresh_device(message):
    print('refresh_device()', message)
    device_list = get_device_list()

    device_list_html = render_template("components/device_list.htm", **locals())

    socketio.emit('refresh_device_response',
                  {'data': {'device_list_html': device_list_html}})
    return device_list


@socketio.on('refresh_application', namespace='/')
def refresh_device(message):
    print('refresh_device()', message)

    device_id = message['device_id']

    application_list = get_application_list(device_id)

    cache.update_device_info(device_id)

    application_list_html = render_template("components/application_list.htm", **locals())

    socketio.emit('refresh_application_response',
                  {'data': {'application_list_html': application_list_html}})
    return application_list
