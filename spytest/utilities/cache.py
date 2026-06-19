import os

_cache = {}
_cache_support = 0  # 0: disable 1: enable 2: group-wise 3: key-wise
_cache_filters = {"ordyaml.include": 1}
_cache_stats = {}


def _bld_key(group, name):
    return "{}--{}".format(group, name)


def dbg_cache():
    if _cache_support == 0:
        return
    for key in _cache.keys():
        print(key, _cache_stats.get(key, [0, 0]))


def add_cache(group, name=None):
    if name:
        _cache_filters[_bld_key(group, name)] = 1
    _cache_filters[group] = 1


def chk_cache(group, name):
    if _cache_support == 0:
        return False
    if _cache_support == 1:
        return True
    if _cache_support == 2:
        return bool(group in _cache_filters)
    return bool(_bld_key(group, name) in _cache_filters)


def get_cache(group, name, default):
    if not chk_cache(group, name):
        value = default
    else:
        key = _bld_key(group, name)
        stats = _cache_stats.setdefault(key, [0, 0])
        if key in _cache:
            value = _cache.get(key)
            stats[0] = stats[0] + 1
        else:
            stats[1] = stats[1] + 1
            value = default
    # print("get_cache({}) = {}".format(name, value))
    return value


def set_cache(group, name, value):
    # print("set_cache({}) = {}".format(name, value))
    if chk_cache(group, name):
        key = _bld_key(group, name)
        _cache[key] = value
        _cache_stats.pop(key, None)


def clr_cache(group, name):
    if chk_cache(group, name):
        _cache.pop(_bld_key(group, name), None)


def init_cache():
    global _cache_support
    try:
        _cache_support = int(os.getenv("SPYTEST_GLOBAL_CACHE_SUPPORT", "0"))
    except Exception:
        _cache_support = 0
