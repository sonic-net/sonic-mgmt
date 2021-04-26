import time
import logging

logger = logging.getLogger(__name__)

config_sources = ['config_db', 'minigraph']


def config_reload(duthost, config_source='config_db', wait=120, start_bgp=True, start_dynamic_buffer=True):
    """
    reload SONiC configuration
    :param duthost: DUT host object
    :param config_source: configuration source either 'config_db' or 'minigraph'
    :param wait: wait timeout for DUT to initialize after configuration reload
    :return:
    """

    if config_source not in config_sources:
        raise ValueError('invalid config source passed in "{}", must be {}'.format(
            config_source,
            ' or '.join(['"{}"'.format(src) for src in config_sources])
        ))

    logger.info('reloading {}'.format(config_source))

    if config_source == 'minigraph':
        if start_dynamic_buffer and duthost.facts['asic_type'] == 'mellanox':
            output = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model', module_ignore_errors=True)
            is_buffer_model_dynamic = (output and output.get('stdout') == 'dynamic')
        else:
            is_buffer_model_dynamic = False
        duthost.shell('config load_minigraph -y &>/dev/null', executable="/bin/bash")
        if start_bgp:
            duthost.shell('config bgp startup all')
        if is_buffer_model_dynamic:
            duthost.shell('enable-dynamic-buffer.py')
        duthost.shell('config save -y')

    if config_source == 'config_db':
        duthost.shell('config reload -y &>/dev/null', executable="/bin/bash")

    time.sleep(wait)
