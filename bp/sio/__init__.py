from flask import Blueprint

bp_io = Blueprint('io', __name__)

from . import routes, events
