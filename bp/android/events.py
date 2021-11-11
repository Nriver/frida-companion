import logging
from __main__ import socketio

logger = logging.getLogger(__name__)


@socketio.on('android_page', namespace='/')
def android_page():
    print('android page')
