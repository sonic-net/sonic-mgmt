import re
import logging
import pprint
from ptf.mask import Mask
import ptf.testutils as testutils
import ptf.packet as scapy
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

MAC_STR = "000000000000"
DEFAULT_FDB_ETHERNET_TYPE = 0x1234
FDB_WAIT_EXPECTED_PACKET_TIMEOUT = 5
BASE_MAC_PREFIX = "02:11:22"

logger = logging.getLogger(__name__)


def MacToInt(mac):
    mac = mac.replace(":", "")
    return int(mac, 16)


def IntToMac(intMac):
    hexStr = hex(intMac)[2:]
    hexStr = MAC_STR[0:12-len(hexStr)] + hexStr
    return ":".join(re.findall(r'.{2}|.+', hexStr))


def get_crm_resources(duthost, resource, status):
    retry_count = 5
    count = 0
    while len(duthost.get_crm_resources().get("main_resources")) == 0 and count < retry_count:
        logger.debug("CRM resources not fully populated, retry after 2 seconds: count: {}".format(count))
        time.sleep(2)
        count = count + 1
    pytest_assert(resource in duthost.get_crm_resources().get("main_resources"),
                  "{} not populated in CRM resources".format(resource))
    return duthost.get_crm_resources().get("main_resources").get(resource).get(status)


def get_fdb_dynamic_mac_count(duthost):
    res = duthost.command('show mac')
    logger.info('"show mac" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
    total_mac_count = 0
    for output_mac in res['stdout_lines']:
        if "dynamic" in output_mac.lower() and BASE_MAC_PREFIX in output_mac.lower():
            total_mac_count += 1
    return total_mac_count


def fdb_table_has_dummy_mac_for_interface(duthost, interface, dummy_mac_prefix=""):
    res = duthost.command('show mac')
    logger.info('"show mac" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))
    for output_mac in res['stdout_lines']:
        if (interface in output_mac and (dummy_mac_prefix in output_mac or dummy_mac_prefix == "")):
            return True
    return False


def fdb_table_has_no_dynamic_macs(duthost):
    return (get_fdb_dynamic_mac_count(duthost) == 0)


def fdb_cleanup(duthosts, rand_one_dut_hostname):
    """ cleanup FDB before and after test run """
    duthost = duthosts[rand_one_dut_hostname]
    if fdb_table_has_no_dynamic_macs(duthost):
        return
    else:
        duthost.command('sonic-clear fdb all')
        pytest_assert(wait_until(100, 2, 0, fdb_table_has_no_dynamic_macs, duthost), "FDB Table Cleanup failed")


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
        pkt[scapy.Dot1Q: 1].type = DEFAULT_FDB_ETHERNET_TYPE
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
    logger.debug('send packet source port id {} smac: {} dmac: {} vlan: {}'
                 .format(source_port, source_mac, dest_mac, vlan_id))
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
    pkt = testutils.simple_arp_packet(
        pktlen=60,
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
    logger.debug('send ARP request packet source port id {} smac: {} dmac: {} vlan: {}'
                 .format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)


def send_arp_reply(ptfadapter, source_port, source_mac, dest_mac, vlan_id):
    """
    send arp reply packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = testutils.simple_arp_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=vlan_id,
        vlan_pcp=0,
        arp_op=2,
        ip_snd='10.10.1.2',
        ip_tgt='10.10.1.3',
        hw_tgt=dest_mac,
        hw_snd=source_mac,
    )
    logger.debug('send ARP reply packet source port id {} smac: {} dmac: {} vlan: {}'
                 .format(source_port, source_mac, dest_mac, vlan_id))
    testutils.send(ptfadapter, source_port, pkt)


def send_recv_eth(ptfadapter, source_ports, source_mac, dest_ports, dest_mac, src_vlan, dst_vlan):
    """
    send ethernet packet and verify it on dest_port
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_port: destination port to receive packet on
    :param dest_mac: destination MAC
    :param vlan_id: VLAN id
    :return:
    """
    pkt = simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=src_vlan
    )
    exp_pkt = simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        vlan_vid=dst_vlan
    )
    if dst_vlan:
        # expect to receive tagged packet:
        # sonic device might modify the 802.1p field,
        # need to use Mask to ignore the priority field.
        exp_pkt = Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Dot1Q, "prio")
    logger.debug('send packet src port {} smac: {} dmac: {} vlan: {} verifying on dst port {}'.format(
        source_ports, source_mac, dest_mac, src_vlan, dest_ports))
    testutils.send(ptfadapter, source_ports[0], pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, dest_ports, timeout=FDB_WAIT_EXPECTED_PACKET_TIMEOUT)
