import json
import functools
import collections
import logging

__author__ = 'yolosec'
logger = logging.getLogger(__name__)


class Config(object):
    """Configuration object, handles file read/write"""

    def __init__(self, json_db=None, *args, **kwargs):
        self.json = json_db

        pass

    @classmethod
    def default_config(cls):
        return cls(json_db={
            'config': {
                'consumer_key': None,
                'consumer_secret': None,
                'access_key': None,
                'access_secret': None
            }
        })

    @classmethod
    def from_json(cls, json_string):
        return cls(json_db=json.loads(json_string, object_pairs_hook=collections.OrderedDict))

    @classmethod
    def from_file(cls, file_name):
        with open(file_name, 'r') as f:
            read_lines = [x.strip() for x in f.read().split('\n')]
            lines = []
            for line in read_lines:
                if line.startswith('//'):
                    continue
                lines.append(line)

            return Config.from_json('\n'.join(lines))

    def ensure_config(self):
        if self.json is None:
            self.json = collections.OrderedDict()
        if 'config' not in self.json:
            self.json['config'] = collections.OrderedDict()

    def has_nonempty_config(self):
        return self.json is not None and 'config' in self.json and len(self.json['config']) > 0

    def get_config(self, key, default=None):
        if not self.has_nonempty_config():
            return default
        return self.json['config'][key] if key in self.json['config'] else default

    def set_config(self, key, val):
        self.ensure_config()
        self.json['config'][key] = val

    def to_string(self):
        return json.dumps(self.json, indent=2) if self.has_nonempty_config() else ""

    # Twitter auth: consumer_key
    @property
    def consumer_key(self):
        return self.get_config('consumer_key')

    @consumer_key.setter
    def consumer_key(self, val):
        self.set_config('consumer_key', val)

    # Twitter auth: consumer_key
    @property
    def consumer_secret(self):
        return self.get_config('consumer_secret')

    @consumer_secret.setter
    def consumer_secret(self, val):
        self.set_config('consumer_secret', val)

    # Twitter auth: access_key
    @property
    def access_key(self):
        return self.get_config('access_key')

    @access_key.setter
    def access_key(self, val):
        self.set_config('access_key', val)

    # Twitter auth: access_secret
    @property
    def access_secret(self):
        return self.get_config('access_secret')

    @access_secret.setter
    def access_secret(self, val):
        self.set_config('access_secret', val)



