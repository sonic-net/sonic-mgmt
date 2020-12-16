import logging
import pytest

from tests.common import config_reload

logger = logging.getLogger(__name__)


def clear_dut_arp_cache(duthost):
    duthost.shell('ip -stats neigh flush all')


def get_po(mg_facts, intf):
    for k, v in mg_facts['minigraph_portchannels'].iteritems():
        if intf in v['members']:
            return k
    return None


def collect_info(duthost):
    if duthost.facts['asic_type'] == "mellanox":
        logger.info('************* Collect information for debug *************')
        duthost.shell('ip link')
        duthost.shell('ip addr')
        duthost.shell('grep . /sys/class/net/Ethernet*/address', module_ignore_errors=True)
        duthost.shell('grep . /sys/class/net/PortChannel*/address', module_ignore_errors=True)
