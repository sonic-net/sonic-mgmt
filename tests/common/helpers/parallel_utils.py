from tests.common import config_reload


def config_reload_parallel_compatible(node, results, *args, **kwargs):
    return config_reload(node, *args, **kwargs)
