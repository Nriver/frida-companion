from flask import render_template

from . import bp_ios


@bp_ios.route('/', methods=['GET'])
def ios():
    return render_template('ios.htm', **locals())
