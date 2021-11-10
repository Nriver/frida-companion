from flask import render_template
from frida import get_device

from utils.cache_helper import cache
from utils.frida_helper import get_device_list, get_application_list, get_device_system
from . import bp_home


@bp_home.route('/', methods=['GET'])
@bp_home.route('/home', methods=['GET'])
def home():
    device_list = get_device_list()
    default_device = None
    try:
        x = get_device(cache.get_device_id())
        default_device = {'name': x.name, 'type': x.type, 'id': x.id, 'system': get_device_system(x.id)}
    except Exception as e:
        print('could not get device id from cache')
        print(e)
    if not default_device:
        default_device = device_list[0]
    cache.update_device_info(default_device['id'])

    application_list = get_application_list(default_device['id'])

    return render_template('index.htm', **locals())
