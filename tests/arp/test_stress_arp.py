import logging
import time
from arp_utils import MacToInt, IntToMac, get_crm_resources, fdb_cleanup, clear_dut_arp_cache
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert, pytest_require

ARP_SRC_MAC = "00:00:01:02:03:04"

logger = logging.getLogger(__name__)

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}

def add_arp(ptf_intf_ipv4_addr, intf1_index, ptfadapter):
    ip_num = 0
    for arp_request_ip in ptf_intf_ipv4_addr:
        arp_request_ip = str(arp_request_ip)
        arp_src_mac = IntToMac(MacToInt(ARP_SRC_MAC) + ip_num)
        ip_num += 1
        pkt = testutils.simple_arp_packet(pktlen=60,
                                    eth_dst='ff:ff:ff:ff:ff:ff',
                                    eth_src=arp_src_mac,
                                    vlan_pcp=0,
                                    arp_op=2,
                                    ip_snd=arp_request_ip,
                                    ip_tgt=arp_request_ip,
                                    hw_snd=arp_src_mac,
                                    hw_tgt='ff:ff:ff:ff:ff:ff'
                                )
        testutils.send_packet(ptfadapter, intf1_index, pkt)
    logger.info("Sending {} arp entries".format(ip_num))

def test_ipv4_arp(duthost, garp_enabled, ip_and_intf_info, intfs_for_test, ptfadapter, get_function_conpleteness_level):
    """
    Send gratuitous ARP (GARP) packet sfrom the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    """
    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "basic"

    ipv4_avaliable = get_crm_resources(duthost, "ipv4_neighbor", "available") - get_crm_resources(duthost, "ipv4_neighbor", "used")
    fdb_avaliable = get_crm_resources(duthost, "fdb_entry", "available") - get_crm_resources(duthost, "fdb_entry", "used")
    pytest_assert(ipv4_avaliable > 0 and fdb_avaliable > 0, "Entries have been filled")

    arp_avaliable = min(ipv4_avaliable, fdb_avaliable)

    pytest_require(garp_enabled, 'Gratuitous ARP not enabled for this device')
    _, ptf_intf_ipv4_hosts, _, _ = ip_and_intf_info
    ptf_intf_ipv4_hosts = list(ptf_intf_ipv4_hosts)[1:arp_avaliable + 1]
    _, _, intf1_index, _, = intfs_for_test

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        loop_times -= 1
        add_arp(ptf_intf_ipv4_hosts, intf1_index, ptfadapter)

        time.sleep(5)

        clear_dut_arp_cache(duthost)
        fdb_cleanup(duthost)

        time.sleep(5)