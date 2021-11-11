from flask import Blueprint

bp_android = Blueprint('android', __name__)

from . import routes, events
