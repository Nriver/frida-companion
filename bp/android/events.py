import logging

from flask import render_template

from bp import socketio

logger = logging.getLogger(__name__)


@socketio.on('android_page', namespace='/')
def android_page():
    print('android page')


@socketio.on('load_classes', namespace='/')
def refresh_device(message):
    print('refresh_device()', message)

    class_list = []

    class_list_html = render_template("components/class_list.htm", **locals())

    socketio.emit('load_class_response',
                  {'data': {'class_list_html': class_list_html}})

    return class_list
