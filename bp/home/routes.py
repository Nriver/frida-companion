from flask import request, render_template

from . import bp_home


@bp_home.route('/', methods=['GET'])
@bp_home.route('/home', methods=['GET'])
def home():
    if request.method == 'POST':
        param = request.values
    else:
        param = request.args
    print(param)
    post_data = request.get_data()
    return render_template('index.htm', **locals())
