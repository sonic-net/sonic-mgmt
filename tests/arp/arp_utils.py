import logging

logger = logging.getLogger(__name__)


def clear_dut_arp_cache(duthost, ns_option = None):
    logger.info("Clearing {} neighbor table".format(duthost.hostname))
    arp_flush_cmd = "ip -stats neigh flush all"
    if ns_option:
        arp_flush_cmd = "sudo ip -stats {} neigh flush all".format(ns_option)
    duthost.shell(arp_flush_cmd)


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

def increment_ipv4_addr(ipv4_addr, incr=1):
    octets = str(ipv4_addr).split('.')
    last_octet = int(octets[-1])
    last_octet += incr
    octets[-1] = str(last_octet)

    return '.'.join(octets)

def increment_ipv6_addr(ipv6_addr, incr=1):
    octets = str(ipv6_addr).split(':')
    last_octet = octets[-1]
    if last_octet == '':
        last_octet = '0'
    incremented_octet = int(last_octet, 16) + incr
    new_octet_str = '{:x}'.format(incremented_octet)

    return ':'.join(octets[:-1]) + ':' + new_octet_str
