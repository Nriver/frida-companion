import json
import logging
import os

import frida

from settings import cache_file
from utils.frida_helper import get_device_system

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

        self.objs = {}

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

    def get_device_id(self):
        return self.data.get('device_id', None)

    def set_device_id(self, device_id):
        self.data['device_id'] = device_id
        self.save()

    def get_device_type(self):
        return self.data.get('device_type', None)

    def set_device_type(self, device_type):
        self.data['device_type'] = device_type
        self.save()

    def get_target_application(self):
        return self.data.get('target_application', None)

    def set_target_application(self, target_application):
        self.data['target_application'] = target_application
        self.save()

    def update_device_info(self, device_id):
        device = frida.get_device(device_id)
        self.data['device_id'] = device.id
        self.data['device_type'] = device.type
        self.data['device_system'] = get_device_system(device_id)
        self.save()

    def save_obj(self, key, obj):
        self.objs[key] = obj

    def get_obj(self, key):
        return self.objs.get(key, None)


cache = Cache()
