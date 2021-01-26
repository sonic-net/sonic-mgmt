from __future__ import print_function, division, absolute_import

import logging
import json
import os
import shutil
import sys

from collections import defaultdict
from threading import Lock

from six import with_metaclass

logger = logging.getLogger(__name__)

CURRENT_PATH = os.path.realpath(__file__)
CACHE_LOCATION = os.path.join(CURRENT_PATH, '../../../_cache')

SIZE_LIMIT = 1000000000  # 1G bytes, max disk usage allowed by cache
ENTRY_LIMIT = 1000000    # Max number of json files allowed in cache.


class Singleton(type):

    _instances = {}
    _lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super(Singleton, cls).__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]


class FactsCache(with_metaclass(Singleton, object)):
    """Singleton class for reading from cache and write to cache.

    Used singleton design pattern. Only a single instance of this class can be initialized.

    Args:
        with_metaclass ([function]): Python 2&3 compatible function from the six library for adding metaclass.
    """
    def __init__(self, cache_location=CACHE_LOCATION):
        self._cache_location = os.path.abspath(cache_location)
        self._cache = defaultdict(dict)

    def _check_usage(self):
        """Check cache usage, raise exception if usage exceeds the limitations.
        """
        total_size = 0
        total_entries = 0
        for root, _, files in os.walk(self._cache_location):
            for f in files:
                fp = os.path.join(root, f)
                total_size += os.path.getsize(fp)
                total_entries += 1

        if total_size > SIZE_LIMIT or total_entries > ENTRY_LIMIT:
            msg = 'Cache usage exceeds limitations. total_size={}, SIZE_LIMIT={}, total_entries={}, ENTRY_LIMIT={}' \
                .format(total_size, SIZE_LIMIT, total_entries, ENTRY_LIMIT)
            raise Exception(msg)

    def read(self, hostname, key):
        """Read cached facts.

        Args:
            hostname (str): Hostname.
            key (str): Name of cached facts.

        Returns:
            obj: Cached object, usually a dictionary.
        """
        # Lazy load
        if hostname in self._cache and key in self._cache[hostname]:
            logger.info('Read cached facts "{}.{}"'.format(hostname, key))
            return self._cache[hostname][key]
        else:
            facts_file = os.path.join(self._cache_location, '{}/{}.json'.format(hostname, key))
            try:
                with open(facts_file) as f:
                    self._cache[hostname][key] = json.load(f)
                    logger.info('Loaded cached facts "{}.{}" from {}'.format(hostname, key, facts_file))
                    return self._cache[hostname][key]
            except (IOError, ValueError) as e:
                logger.error('Load json file "{}" failed with exception: {}'\
                    .format(os.path.abspath(facts_file), repr(e)))
                return {}

    def write(self, hostname, key, value):
        """Store facts to cache.

        Args:
            hostname (str): Hostname.
            key (str): Name of cached facts.
            value (obj): Value of cached facts. Usually a dictionary.

        Returns:
            boolean: Caching facts is successful or not.
        """
        self._check_usage()
        facts_file = os.path.join(self._cache_location, '{}/{}.json'.format(hostname, key))
        try:
            host_folder = os.path.join(self._cache_location, hostname)
            if not os.path.exists(host_folder):
                logger.info('Create cache dir {}'.format(host_folder))
                os.makedirs(host_folder)

            with open(facts_file, 'w') as f:
                json.dump(value, f, indent=2)
                self._cache[hostname][key] = value
                logger.info('Cached facts "{}.{}" under {}'.format(hostname, key, host_folder))
                return True
        except (IOError, ValueError) as e:
            logger.error('Dump json file "{}" failed with exception: {}'.format(facts_file, repr(e)))
            return False

    def cleanup(self, hostname=None):
        """Cleanup cached json files.

        Args:
            hostname (str, optional): Hostname. Defaults to None.
        """
        if hostname:
            sub_items = os.listdir(self._cache_location)
            if hostname in sub_items:
                host_folder = os.path.join(self._cache_location, hostname)
                logger.info('Clean up cached facts under "{}"'.format(host_folder))
                shutil.rmtree(host_folder)
            else:
                logger.error('Sub-folder for host "{}" is not found'.format(hostname))
        else:
            logger.info('Clean up all cached facts under "{}"'.format(self._cache_location))
            shutil.rmtree(self._cache_location)


def cached(name):
    """Decorator for enabling cache for facts.

    The cached facts are to be stored by <name>.json. Because the cached json files must be stored under subfolder for
    each host, this decorator can only be used for bound method of class which is subclass of AnsibleHostBase.

    Args:
        name ([str]): Name of the cached facts.

    Returns:
        [function]: Decorator function.
    """
    cache = FactsCache()
    def decorator(target):
        def wrapper(*args, **kwargs):
            hostname = getattr(args[0], 'hostname', None)
            if not hostname or not isinstance(hostname, str):
                raise Exception('Decorator is only applicable to bound method of class AnsibleHostBase and its sub-classes')
            cached_facts = cache.read(hostname, name)
            if cached_facts:
                return cached_facts
            else:
                facts = target(*args, **kwargs)
                cache.write(hostname, name, facts)
                return facts
        return wrapper
    return decorator


if __name__ == '__main__':
    cache = FactsCache()
    if len(sys.argv) == 2:
        hostname = sys.argv[1]
    else:
        hostname = None
    cache.cleanup(hostname)
