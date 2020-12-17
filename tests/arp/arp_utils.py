import logging

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

def increment_ipv6_addr(ipv6_addr, incr=1):
    octets = str(ipv6_addr).split(':')
    last_octet = octets[-1]
    if last_octet == '':
        last_octet = '0'
    incremented_octet = int(last_octet, 16) + incr
    new_octet_str = '{:x}'.format(incremented_octet)

    return ':'.join(octets[:-1]) + ':' + new_octet_str