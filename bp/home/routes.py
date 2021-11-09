from flask import render_template

from utils.frida_helper import get_device_list, get_application_list
from . import bp_home


@bp_home.route('/', methods=['GET'])
@bp_home.route('/home', methods=['GET'])
def home():
    device_list = get_device_list()
    default_device = device_list[0]
    application_list = []
    if default_device['type'] == 'usb':
        application_list = get_application_list()

    return render_template('index.htm', **locals())
