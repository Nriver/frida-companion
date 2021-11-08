from flask import Flask
from flask_socketio import SocketIO

from settings import debug, SECRET_KEY

socketio = SocketIO()


def create_app():
    app = Flask(__name__)
    app.debug = debug
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

    # flask blueprints

    # socketio test
    from bp.sio.routes import bp_io
    app.register_blueprint(bp_io, url_prefix='/')

    # home page
    from bp.home import bp_home
    app.register_blueprint(bp_home, url_prefix='/')

    socketio.init_app(app)

    # ignore ending slash
    app.url_map.strict_slashes = False

    # print all route
    print(app.url_map)

    return app
