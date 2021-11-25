import re
import logging
import pprint
import ptf.testutils as testutils
import ptf.packet as scapy

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

MAC_STR = "000000000000"
DEFAULT_FDB_ETHERNET_TYPE = 0x1234

logger = logging.getLogger(__name__)

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
    logger.info('"show mac" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
    total_mac_count = 0
    for l in res['stdout_lines']:
        if "dynamic" in l.lower():
            total_mac_count += 1
    return total_mac_count


def fdb_table_has_no_dynamic_macs(duthost):
    return (get_fdb_dynamic_mac_count(duthost) == 0)

def fdb_cleanup(duthosts, rand_one_dut_hostname):
    """ cleanup FDB before and after test run """
    duthost = duthosts[rand_one_dut_hostname]
    if fdb_table_has_no_dynamic_macs(duthost):
        return
    else:
        duthost.command('sonic-clear fdb all')
        pytest_assert(wait_until(20, 2, 0, fdb_table_has_no_dynamic_macs, duthost), "FDB Table Cleanup failed")

def simple_eth_packet(
    pktlen=60,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    vlan_vid=0,
    vlan_pcp=0
):
    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if vlan_vid or vlan_pcp:
        pktlen += 4
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
        pkt[scapy.Dot1Q : 1].type = DEFAULT_FDB_ETHERNET_TYPE
    else:
        pkt.type = DEFAULT_FDB_ETHERNET_TYPE
    pkt = pkt / ("0" * (pktlen - len(pkt)))

    return pkt

def send_eth(ptfadapter, source_port, source_mac, dest_mac, vlan_id):
    """
    send ethernet packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=vlan_id
    )
    logger.debug('send packet source port id {} smac: {} dmac: {} vlan: {}'.format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)


def send_arp_request(ptfadapter, source_port, source_mac, dest_mac, vlan_id):
    """
    send arp request packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = testutils.simple_arp_packet(pktlen=60,
                eth_dst=dest_mac,
                eth_src=source_mac,
                vlan_vid=vlan_id,
                vlan_pcp=0,
                arp_op=1,
                ip_snd='10.10.1.3',
                ip_tgt='10.10.1.2',
                hw_snd=source_mac,
                hw_tgt='ff:ff:ff:ff:ff:ff',
                )
    logger.debug('send ARP request packet source port id {} smac: {} dmac: {} vlan: {}'.format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)
