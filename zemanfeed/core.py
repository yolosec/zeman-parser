import json
import os
import os.path
import pid
from datetime import datetime
from __init__ import CONFIG_DIR, CONFIG_FILE
import util, errors
from config import Config


class Core(object):
    def __init__(self, piddir=CONFIG_DIR, *args, **kwargs):
        """Init the core functions"""
        self.pidlock = pid.PidFile(pidname='zeman-cli.pid', piddir=piddir)
        self.pidlock_created = False

    def pidlock_create(self):
        if not self.pidlock_created:
            self.pidlock.create()
            self.pidlock_created = True

    def pidlock_check(self):
        return self.pidlock.check()

    def pidlock_get_pid(self):
        filename = self.pidlock.filename
        if filename and os.path.isfile(filename):
            try:
                with open(filename, "r") as fh:
                    fh.seek(0)
                    pid = int(fh.read().strip())
                    return pid
            except:
                pass

        return None

    @staticmethod
    def get_config_file_path():
        """Returns basic configuration file"""
        return os.path.join(CONFIG_DIR, CONFIG_FILE)

    @staticmethod
    def config_file_exists():
        conf_name = Core.get_config_file_path()
        return os.path.isfile(conf_name)

    @staticmethod
    def is_configuration_nonempty(config):
        return config is not None and config.has_nonempty_config()

    @staticmethod
    def read_configuration():
        if not Core.config_file_exists():
            return None

        conf_name = Core.get_config_file_path()
        return Config.from_file(conf_name)

    @staticmethod
    def write_configuration(cfg):
        util.make_or_verify_dir(CONFIG_DIR, mode=0o755)

        conf_name = Core.get_config_file_path()
        with os.fdopen(os.open(conf_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as config_file:
            config_file.write(cfg.to_string() + "\n\n")
        return conf_name


