import re
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

MAC_STR = "000000000000"
BASE_MAC_PREFIX = "00:00:01"


def clear_dut_arp_cache(duthost, ns_option=None):
    logger.info("Clearing {} neighbor table".format(duthost.hostname))
    arp_flush_cmd = "ip -stats neigh flush all"
    if ns_option:
        arp_flush_cmd = "ip -stats {} neigh flush all".format(ns_option)
    duthost.shell(arp_flush_cmd)


def get_po(mg_facts, intf):
    for k, v in list(mg_facts['minigraph_portchannels'].items()):
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


def MacToInt(mac):
    mac = mac.replace(":", "")
    return int(mac, 16)


def IntToMac(intMac):
    hexStr = hex(intMac)[2:]
    hexStr = MAC_STR[0:12-len(hexStr)] + hexStr
    return ":".join(re.findall(r'.{2}|.+', hexStr))


def get_crm_resources(duthost, resource, status):
    return duthost.get_crm_resources().get("main_resources").get(resource).get(status)


def get_fdb_dynamic_mac_count(duthost):
    res = duthost.command('show mac')
    total_mac_count = 0
    for mac_entry in res['stdout_lines']:
        if "dynamic" in mac_entry.lower() and BASE_MAC_PREFIX in mac_entry.lower():
            total_mac_count += 1
    return total_mac_count


def fdb_table_has_no_dynamic_macs(duthost):
    return (get_fdb_dynamic_mac_count(duthost) == 0)


def fdb_cleanup(duthost):
    """ cleanup FDB before and after test run """
    if fdb_table_has_no_dynamic_macs(duthost):
        return
    else:
        duthost.command('fdbclear')
        pytest_assert(wait_until(200, 2, 0, lambda: fdb_table_has_no_dynamic_macs(duthost) is True),
                      "FDB Table Cleanup failed")
