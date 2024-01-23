import logging

import frida
from flask import render_template

from bp import socketio
from utils.adb_helper import is_frida_server_running
from utils.cache_helper import cache
from utils.frida_helper import get_device_list, get_application_list, run_frida_server, get_device_system, \
    get_all_frida_gadget_for_android

logger = logging.getLogger(__name__)


@socketio.on('home_page', namespace='/')
def home_page():
    print('home page')


@socketio.on('refresh_device', namespace='/')
def refresh_device(message):
    print('refresh_device()', message)
    device_list = get_device_list()

    device_list_html = render_template("components/device_list.htm", **locals())

    socketio.emit('refresh_device_response',
                  {'data': {'device_list_html': device_list_html}})
    return device_list


@socketio.on('refresh_application', namespace='/')
def refresh_application(message):
    print('refresh_application()', message)

    device_id = message['device_id']

    application_list = get_application_list(device_id)

    cache.update_device_info(device_id)

    application_list_html = render_template("components/application_list.htm", **locals())

    socketio.emit('refresh_application_response',
                  {'data': {'application_list_html': application_list_html}})
    return application_list


@socketio.on('start_application', namespace='/')
def start_application(message):
    print('start_application()', message)
    device_id = message['device_id']
    application = message['application']
    cache.set_target_application(application)
    device = frida.get_device(device_id)

    device_system = get_device_system(device_id)
    print(device_system)
    # start frida-server
    # only android devices need to start frida server manually
    # iOS device are handled by Cydia packages
    if device_system == 'android':
        if not is_frida_server_running(device_id):
            run_frida_server(device_id)
        print('server started!')
    pid = None
    try:
        pid = device.spawn([application, ])
    except Exception as e:
        if 'need Gadget to attach' in str(e):
            # device_arch = get_android_architecture(device_id)
            frida_version = frida.__version__
            # get_frida_gadget(frida_version, device_arch)
            get_all_frida_gadget_for_android(frida_version)
            pid = device.spawn([application, ])
    if not pid:
        print('spawn error')
        socketio.emit('start_application_response', {'success': False})
        return False
    session = device.attach(pid)
    print(session)

    # startup script
    startup_script_string = f'''console.log("hello, {application} started, startup script executed!")'''
    script = session.create_script(startup_script_string)
    script.load()

    device.resume(pid)
    # session.detach()

    cache.save_obj('session', session)

    print('start complete')

    # send redirect
    if device_system == 'android':
        socketio.emit('start_application_response', {'success': True, 'next': '/android'})
    elif device_system == 'ios':
        socketio.emit('start_application_response', {'success': True, 'next': '/ios'})
    else:
        socketio.emit('start_application_response', {'success': True, 'next': '/general'})
    return True
