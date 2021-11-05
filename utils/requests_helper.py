import requests
from tqdm import tqdm

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


def requests_get_download(url, save_path):
    response = requests.get(url, stream=True, proxies=PROXIES, verify=not USE_PROXY)
    total_size_in_bytes = int(response.headers.get('content-length', 0))
    print(url)
    print(total_size_in_bytes)
    block_size = 1024
    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True)
    with open(save_path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)
    progress_bar.close()
    if total_size_in_bytes != 0 and progress_bar.n != total_size_in_bytes:
        print("ERROR, something went wrong")
        exit()
