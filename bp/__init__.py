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

    # android page
    from bp.android import bp_android
    app.register_blueprint(bp_android, url_prefix='/android')

    # android page
    from bp.ios import bp_ios
    app.register_blueprint(bp_ios, url_prefix='/ios')

    # general page
    from bp.general import bp_general
    app.register_blueprint(bp_general, url_prefix='/general')

    # init app
    socketio.init_app(app)

    # ignore ending slash
    app.url_map.strict_slashes = False

    # print all route
    print(app.url_map)

    return app
