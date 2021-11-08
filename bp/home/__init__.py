from flask import Blueprint

bp_home = Blueprint('home', __name__)

from . import routes, events
