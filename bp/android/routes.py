from flask import render_template

from . import bp_android


@bp_android.route('/', methods=['GET'])
def android():
    return render_template('android.htm', **locals())
