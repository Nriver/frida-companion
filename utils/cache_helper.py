import json
import logging
import os

from settings import cache_file

logger = logging.getLogger(__name__)


# file cache

class Cache:
    def __init__(self):
        self.data = {}
        if os.path.exists(cache_file):
            with open(cache_file, encoding='utf-8') as f:
                content = f.read()
                if not content:
                    return
                self.data = json.loads(content)

    def save(self):
        logger.info('save cache')
        print(self.data)
        with open(cache_file, 'w', encoding='utf-8') as f:
            f.write(json.dumps(self.data, ensure_ascii=False, indent=4))

    def get_frida_update_time(self):
        return self.data.get('frida_update_time', None)

    def set_frida_update_time(self, ts):
        self.data['frida_update_time'] = ts
        self.save()


cache = Cache()
