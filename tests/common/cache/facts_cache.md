# Facts Cache

To run test scripts, we frequently need to gather facts from various devices again and again. Most of the facts gatherings need to run some commands on remote devices through SSH connection, parse the commands output and return the results. Most of the time, the facts to be gathered are unchanged, like DUT HWSKU, platform, etc. For the less frequently changed facts, we can cache them for quicker access to save a lot of overhead for gathering them each time. Then we can improve the overall time required for running all the tests.

# Cache Design

To simplify the design, we use local (sonic-mgmt container) pickle files to cache information. Although reading from local file is slower than reading from memory, it is still much faster than running commands on remote host through SSH connection and parsing the output. Only the first reading of cached information needs to load from file. Subsequent reading are from a runtime dictionary, the performance is equivalent to reading from memory. A dedicated folder (by default `tests/_cache`) is used to store the cached pickle files. The pickle files are grouped into sub-folders by zone (usually hostname, but the zone name can also be something else that unique, like testbed name). For example, file `tests/_cache/vlab-01/basic_facts.pickle` caches some basic facts of host `vlab-01`.

The cache function is mainly implemented in below file:
```
sonic-mgmt/tests/common/cache/facts_cache.py
```

A singleton class FactsCache is implemented. This class supports these interfaces:
* `read(self, zone, key)`
* `write(self, zone, key, value)`
* `cleanup(self, zone=None)`

The FactsCache class has a dictionary for holding the cached facts in memory. When the `read` method is called, it firstly read `self._cache[zone][key]` from memory. If not found, it will try to load the pickle file. If anything wrong with the pickle file, it will return an empty dictionary.

When the `write` method is called, it will store facts in memory like `self._cache[zone][key] = value`. Then it will also try to dump the facts to pickle file `tests/_cache/<zone>/<key>.pickle`.

Because `pickle` library is used for caching, all the objects supported by the `pickle` library can be cached.

# Clean up facts

The `cleanup` function is for cleaning the stored pickle files.

When the `facts_cache.py` script is directly executed with an argument, it will call the `cleanup` function to remove stored pickle files for host specified by the first argument. If it is executed without argument, then all the stored pickle files will be removed.

When `testbed-cli.sh deploy-mg` is executed for specified testbed, the ansible playbook will run `facts_cache.py` to remove stored pickle files for current testbed as well.

# Use cache

There are two ways to use the cache function.

## Use decorator `facts_cache.py::cached`

```
from tests.common.cache import cached

class SonicHost(AnsibleHostBase):

...

    @cached(name='basic_facts')
    def _gather_facts(self):
...
```

The `cached` decorator supports name argument which correspond to the `key` argument of `read(self, zone, key)` and `write(self, zone, key, value)`.
The `cached` decorator can only be used on an bound method of class which is subclass of AnsibleHostBase.

## Explicitly use FactsCache

* Import FactsCache and grab the cache instance

```
from tests.common.cache import FactsCache

cache = FactsCache()
```

* Use code like below

```

def get_some_facts(self, *args):
    cached_facts = cache.read(self.hostname, 'some_facts')
    if cached_facts:
        return cached_facts

    # Code to gather the facts from host.
    facts = self._do_stuff_to_gather_facts()
    cache.write(self.hostname, 'some_facts', facts)
    return facts

```

* Another example
```
def get_something():
    info = cache.read('common', 'some_info')
    if info:
        return info
    # Code to get the info
    info = _do_stuff_to_get_info()
    cache.write('common', 'some_info', info)
    return info
```

# Cached facts lifecycle in nightly test

* During `testbed-cli.sh deploy-mg` step of testbed deployment, all cached pickle files are removed.
* Use `pytest test_script1.py test_script2.py` to run one set of test scripts.
  * First encounter of cache enabled facts:
    * No cache in memory.
    * No cache in pickle file.
    * Gather from remote host.
    * Store in memory.
    * Store in pickle file.
    * Return the facts.
  * Subsequent encounter of cache enabled facts.
    * Cache in memory, read from memory. Return the facts.
* Use `pytest test_script3.py test_script4.py` to run another set of test scripts.
  * First encounter of cache enabled facts:
    * No cache in memory.
    * Cache in pickle file. Load from pickle file.
    * Store in memory.
    * Return the facts.
  * Subsequent encounter of cache enabled facts.
    * Cache in memory, read from memory. Return the facts.
