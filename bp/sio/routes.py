from __main__ import socketio

from flask import request, render_template

from . import bp_io


@bp_io.route('/test', methods=['GET', 'POST'])
def test():
    if request.method == 'POST':
        param = request.values
    else:
        param = request.args
    print(param)
    post_data = request.get_data()
    socketio.emit('update',
                  {'data': {'url': request.url, 'Request method': request.method, 'get_data()': post_data.decode(
                      'utf-8'), 'Header': list(request.headers.items()), 'Param': param, 'cookie': request.cookies}})
    return 'test OK'


@bp_io.route('/io/', methods=['GET', 'POST'])
def io_page():
    if request.method == 'POST':
        param = request.values
    else:
        param = request.args
    print(param)
    post_data = request.get_data()
    print('post_data', post_data)
    return render_template('io.htm', **locals())
