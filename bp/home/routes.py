from flask import request, render_template

from utils.frida_helper import get_device_list
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
    device_list = get_device_list()
    return render_template('index.htm', **locals())
