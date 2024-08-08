import logging
import time
import pytest
from .arp_utils import MacToInt, IntToMac, get_crm_resources, fdb_cleanup, \
                      clear_dut_arp_cache, increment_ipv6_addr, get_fdb_dynamic_mac_count
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert, pytest_require
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, in6_getnsmac, \
                      in6_getnsma, inet_pton, inet_ntop, socket
from ipaddress import ip_address, ip_network
from tests.common.utilities import wait_until
from tests.common.fixtures.ptfhost_utils import skip_traffic_test   # noqa F401

ARP_BASE_IP = "172.16.0.1/16"
ARP_SRC_MAC = "00:00:01:02:03:04"
ENTRIES_NUMBERS = 12000

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

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


def genrate_ipv4_ip():
    ipv4_addr = ip_network(ARP_BASE_IP.encode().decode(), strict=False)
    ptf_intf_ipv4_hosts = ipv4_addr.hosts()
    return list(ptf_intf_ipv4_hosts)


def test_ipv4_arp(duthost, garp_enabled, ip_and_intf_info, intfs_for_test,
                  ptfadapter, get_function_conpleteness_level, skip_traffic_test):  # noqa F811
    """
    Send gratuitous ARP (GARP) packet sfrom the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    """
    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "debug"

    ipv4_avaliable = get_crm_resources(duthost, "ipv4_neighbor", "available") - \
        get_crm_resources(duthost, "ipv4_neighbor", "used")
    fdb_avaliable = get_crm_resources(duthost, "fdb_entry", "available") - \
        get_crm_resources(duthost, "fdb_entry", "used")
    pytest_assert(ipv4_avaliable > 0 and fdb_avaliable > 0, "Entries have been filled")

    arp_avaliable = min(min(ipv4_avaliable, fdb_avaliable), ENTRIES_NUMBERS)

    pytest_require(garp_enabled, 'Gratuitous ARP not enabled for this device')
    ptf_intf_ipv4_hosts = genrate_ipv4_ip()
    ptf_intf_ipv4_hosts = ptf_intf_ipv4_hosts[1:arp_avaliable + 1]
    _, _, intf1_index, _, = intfs_for_test

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        loop_times -= 1
        try:
            add_arp(ptf_intf_ipv4_hosts, intf1_index, ptfadapter)
            if not skip_traffic_test:
                # There is a certain probability of hash collision, we set the percentage as 1% here
                # The entries we add will not exceed 10000, so the number we tolerate is 100
                logger.debug("Expected route number: {}, real route number {}"
                             .format(arp_avaliable, get_fdb_dynamic_mac_count(duthost)))
                pytest_assert(wait_until(20, 1, 0,
                                         lambda: abs(arp_avaliable - get_fdb_dynamic_mac_count(duthost)) < 100),
                              "ARP Table Add failed")
        finally:
            clear_dut_arp_cache(duthost)
            fdb_cleanup(duthost)

            time.sleep(5)


def generate_global_addr(mac):
    parts = mac.split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fc02:1000::{}".format(":".join(ipv6Parts))
    ipv6 = str(ip_address(ipv6.encode().decode()))
    return ipv6


def ipv6_packets_for_test(ip_and_intf_info, fake_src_mac, fake_src_addr):
    _, _, src_addr_v6, _, _ = ip_and_intf_info
    fake_src_mac = fake_src_mac

    tgt_addr = increment_ipv6_addr(src_addr_v6)
    multicast_tgt_addr = in6_getnsma(inet_pton(socket.AF_INET6, tgt_addr))
    multicast_tgt_mac = in6_getnsmac(multicast_tgt_addr)

    ns_pkt = Ether(src=fake_src_mac, dst=multicast_tgt_mac)
    ns_pkt /= IPv6(dst=inet_ntop(socket.AF_INET6, multicast_tgt_addr), src=fake_src_addr)
    ns_pkt /= ICMPv6ND_NS(tgt=tgt_addr)
    ns_pkt /= ICMPv6NDOptSrcLLAddr(lladdr=fake_src_mac)

    return ns_pkt


def add_nd(ptfadapter, ip_and_intf_info, ptf_intf_index, nd_avaliable):
    for entry in range(0, nd_avaliable):
        nd_entry_mac = IntToMac(MacToInt(ARP_SRC_MAC) + entry)
        fake_src_addr = generate_global_addr(nd_entry_mac)
        ns_pkt = ipv6_packets_for_test(ip_and_intf_info, nd_entry_mac, fake_src_addr)

        testutils.send_packet(ptfadapter, ptf_intf_index, ns_pkt)
    logger.info("Sending {} ipv6 neighbor entries".format(nd_avaliable))


def test_ipv6_nd(duthost, ptfhost, config_facts, tbinfo, ip_and_intf_info,
                 ptfadapter, get_function_conpleteness_level, proxy_arp_enabled, skip_traffic_test):    # noqa F811
    _, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_ipv6_addr = increment_ipv6_addr(ptf_intf_ipv6_addr)
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')
    pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "debug"

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]
    ipv6_avaliable = get_crm_resources(duthost, "ipv6_neighbor", "available") - \
        get_crm_resources(duthost, "ipv6_neighbor", "used")
    fdb_avaliable = get_crm_resources(duthost, "fdb_entry", "available") - \
        get_crm_resources(duthost, "fdb_entry", "used")
    pytest_assert(ipv6_avaliable > 0 and fdb_avaliable > 0, "Entries have been filled")

    nd_avaliable = min(min(ipv6_avaliable, fdb_avaliable), ENTRIES_NUMBERS)

    while loop_times > 0:
        loop_times -= 1
        try:
            add_nd(ptfadapter, ip_and_intf_info, ptf_intf_index, nd_avaliable)
            if not skip_traffic_test:
                # There is a certain probability of hash collision, we set the percentage as 1% here
                # The entries we add will not exceed 10000, so the number we tolerate is 100
                logger.debug("Expected route number: {}, real route number {}"
                             .format(nd_avaliable, get_fdb_dynamic_mac_count(duthost)))
                pytest_assert(wait_until(20, 1, 0,
                                         lambda: abs(nd_avaliable - get_fdb_dynamic_mac_count(duthost)) < 100),
                              "Neighbor Table Add failed")
        finally:
            clear_dut_arp_cache(duthost)
            fdb_cleanup(duthost)
            # Wait for 10 seconds before starting next loop
            time.sleep(10)
