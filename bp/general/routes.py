from flask import render_template

from . import bp_general


@bp_general.route('/', methods=['GET'])
def general():
    return render_template('general.htm', **locals())
