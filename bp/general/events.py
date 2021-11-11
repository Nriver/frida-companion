import logging
from __main__ import socketio

logger = logging.getLogger(__name__)


@socketio.on('general_page', namespace='/')
def general_page():
    print('general page')
