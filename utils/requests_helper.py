import requests

from settings import PROXIES, USE_PROXY

if USE_PROXY:
    # disable warning if use proxy
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def requests_get(url):
    ret = None
    try:
        ret = requests.get(url, proxies=PROXIES, verify=not USE_PROXY)
    except Exception as e:
        print('If github is not available, you can set USE_PROXY to True and set PROXIES.')
        print('Exception', e)
    return ret
