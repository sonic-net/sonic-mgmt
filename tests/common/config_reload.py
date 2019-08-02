import time
import logging

logger = logging.getLogger(__name__)

config_sources = ['config_db', 'minigraph']


def config_reload(duthost, config_source='config_db', wait=120):
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
        duthost.command('config load_minigraph -y')
        duthost.command('config save -y')

    if config_source == 'config_db':
        duthost.command('config reload -y')

    time.sleep(wait)
