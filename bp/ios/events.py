import logging

from bp import socketio

logger = logging.getLogger(__name__)


@socketio.on('ios_page', namespace='/')
def ios_page():
    print('ios page')
