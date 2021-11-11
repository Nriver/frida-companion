from flask import Blueprint

bp_general = Blueprint('general', __name__)

from . import routes, events
