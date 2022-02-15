import json
import logging
from functools import partial
from collections.abc import MutableMapping


class Config:
    def add(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return str(self.__dict__)


def parse_config(config, target):
    for key, value in config.items():
        if isinstance(value, MutableMapping):
            target.__dict__[key] = parse_config(value, Config())
        else:
            target.add(**{key: value})
    return target

def load_config(configfile):
    """
    Load basic config
    Args:
        configfile: config file name (JSON format)
    Returns:
        A logger, command line args and a UDP client
    """
    logger = logging.getLogger('main')
    with open(configfile, 'r') as f:
        config = parse_config(json.load(f), Config())
    log_level = {
        'notset': 0,
        'debug': 10,
        'info': 20,
        'warning': 30,
        'error': 40,
        'critical': 50,
    }
    logger.setLevel(log_level[config.level.lower()])
    return config

if __name__ == '__main__':
    config = {'dest': {'hostname': 'localhost', 'port': 1700}, 'src': {'hostname': 'localhost', 'port': 1701}, 'level': 'debug'}
    c = parse_config(config)
