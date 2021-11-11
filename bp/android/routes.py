from flask import render_template, redirect

from utils.cache_helper import cache
from . import bp_android


@bp_android.route('/', methods=['GET'])
def android():
    print('android page')
    # load frida session from cache
    session = cache.get_obj('session')
    # go back to application select if session not found
    if not session:
        return redirect('/')

    print(session)
    return render_template('android.htm', **locals())
