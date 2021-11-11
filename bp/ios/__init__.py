from flask import Blueprint

bp_ios = Blueprint('ios', __name__)

from . import routes, events
