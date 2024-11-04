import logging
import time
import pytest
import random
from .arp_utils import MacToInt, IntToMac, get_crm_resources, fdb_cleanup, \
                      clear_dut_arp_cache, get_fdb_dynamic_mac_count
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert, pytest_require
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, in6_getnsmac, \
                      in6_getnsma, inet_pton, inet_ntop, socket
from ipaddress import ip_address, ip_network
from tests.common.utilities import wait_until, increment_ipv6_addr
from tests.common.errors import RunAnsibleModuleFail

import threading
from tests.common.utilities import InterruptableThread


ARP_BASE_IP = "172.16.0.1/16"
ARP_SRC_MAC = "00:00:01:02:03:04"
ENTRIES_NUMBERS = 12000
TEST_CONNTRACK_TIMEOUT = 1000
TEST_INCOMPLETE_NEIGHBOR_CNT = 10

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


@pytest.fixture(autouse=True)
def arp_cache_fdb_cleanup(duthost):
    try:
        clear_dut_arp_cache(duthost)
        fdb_cleanup(duthost)
    except RunAnsibleModuleFail as e:
        if 'Failed to send flush request: No such file or directory' in str(e):
            logger.warning("Failed to clear arp cache or cleanup fdb table, file may not exist yet")
        else:
            raise e

    time.sleep(5)

    yield

    # Ensure clean test environment even after failing
    try:
        clear_dut_arp_cache(duthost)
        fdb_cleanup(duthost)
    except RunAnsibleModuleFail as e:
        if 'Failed to send flush request: No such file or directory' in str(e):
            logger.warning("Failed to clear arp cache or cleanup fdb table, file may not exist yet")
        else:
            raise e

    time.sleep(10)


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
                  ptfadapter, get_function_completeness_level):
    """
    Send gratuitous ARP (GARP) packet sfrom the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    """
    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = "debug"
    asic_type = duthost.facts['asic_type']
    ipv4_available = get_crm_resources(duthost, "ipv4_neighbor", "available")
    fdb_available = get_crm_resources(duthost, "fdb_entry", "available")
    pytest_assert(ipv4_available > 0 and fdb_available > 0, "Entries have been filled")

    arp_available = min(min(ipv4_available, fdb_available), ENTRIES_NUMBERS)

    pytest_require(garp_enabled, 'Gratuitous ARP not enabled for this device')
    ptf_intf_ipv4_hosts = genrate_ipv4_ip()
    ptf_intf_ipv4_hosts = ptf_intf_ipv4_hosts[1:arp_available + 1]
    _, _, intf1_index, _, = intfs_for_test

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    while loop_times > 0:
        loop_times -= 1
        try:
            add_arp(ptf_intf_ipv4_hosts, intf1_index, ptfadapter)
            if asic_type != 'vs':
                # There is a certain probability of hash collision, we set the percentage as 1% here
                # The entries we add will not exceed 10000, so the number we tolerate is 100
                logger.debug("Expected route number: {}, real route number {}"
                             .format(arp_available, get_fdb_dynamic_mac_count(duthost)))
                pytest_assert(wait_until(20, 1, 0,
                                         lambda: abs(arp_available - get_fdb_dynamic_mac_count(duthost)) < 250),
                              "ARP Table Add failed")
        finally:
            try:
                clear_dut_arp_cache(duthost)
                fdb_cleanup(duthost)
            except RunAnsibleModuleFail as e:
                if 'Failed to send flush request: No such file or directory' in str(e):
                    logger.warning("Failed to clear arp cache, file may not exist yet")
                else:
                    raise e

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


# generate neighbor solicitation packet for test
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


def add_nd(ptfadapter, ip_and_intf_info, ptf_intf_index, nd_available):
    for entry in range(0, nd_available):
        nd_entry_mac = IntToMac(MacToInt(ARP_SRC_MAC) + entry)
        fake_src_addr = generate_global_addr(nd_entry_mac)
        ns_pkt = ipv6_packets_for_test(ip_and_intf_info, nd_entry_mac, fake_src_addr)

        testutils.send_packet(ptfadapter, ptf_intf_index, ns_pkt)
    logger.info("Sending {} ipv6 neighbor entries".format(nd_available))


def test_ipv6_nd(duthost, ptfhost, config_facts, tbinfo, ip_and_intf_info,
                 ptfadapter, get_function_completeness_level, proxy_arp_enabled):
    _, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_ipv6_addr = increment_ipv6_addr(ptf_intf_ipv6_addr)
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')
    pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = "debug"
    asic_type = duthost.facts['asic_type']
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]
    ipv6_available = get_crm_resources(duthost, "ipv6_neighbor", "available")
    fdb_available = get_crm_resources(duthost, "fdb_entry", "available")
    pytest_assert(ipv6_available > 0 and fdb_available > 0, "Entries have been filled")

    nd_available = min(min(ipv6_available, fdb_available), ENTRIES_NUMBERS)

    while loop_times > 0:
        loop_times -= 1
        try:
            add_nd(ptfadapter, ip_and_intf_info, ptf_intf_index, nd_available)
            if asic_type != 'vs':
                # There is a certain probability of hash collision, we set the percentage as 1% here
                # The entries we add will not exceed 10000, so the number we tolerate is 100
                logger.debug("Expected route number: {}, real route number {}"
                             .format(nd_available, get_fdb_dynamic_mac_count(duthost)))
                pytest_assert(wait_until(20, 1, 0,
                                         lambda: abs(nd_available - get_fdb_dynamic_mac_count(duthost)) < 250),
                              "Neighbor Table Add failed")
        finally:
            try:
                clear_dut_arp_cache(duthost)
                fdb_cleanup(duthost)
            except RunAnsibleModuleFail as e:
                if 'Failed to send flush request: No such file or directory' in str(e):
                    logger.warning("Failed to clear arp cache, file may not exist yet")
                else:
                    raise e
            # Wait for 10 seconds before starting next loop
            time.sleep(10)


# This is similar to function add_nd except it will keep adding nd entry until a stop event
# is set. A neighbor solicitation will be generated, and the packet will be sent to dut
# from ptf. Ideally, this should keep neighbors in INCOMPLETE state, although sometimes
# there could be delay in processing and neighbors would fall out of INCOMPLETE
def add_nd_nonstop(ptfadapter, ip_and_intf_info, ptf_intf_index, nd_available, stop_event):
    while not stop_event.is_set():
        entry = random.randrange(0, nd_available)
        nd_entry_mac = IntToMac(MacToInt(ARP_SRC_MAC) + entry)
        fake_src_addr = generate_global_addr(nd_entry_mac)
        ns_pkt = ipv6_packets_for_test(ip_and_intf_info, nd_entry_mac, fake_src_addr)
        testutils.send_packet(ptfadapter, ptf_intf_index, ns_pkt)
        time.sleep(0.2)


def send_ipv6_echo_request(ptfadapter, dut_mac, ip_and_intf_info, ptf_intf_index, nd_available, tgt_cnt):
    for i in range(tgt_cnt):
        entry = random.randrange(0, nd_available)
        nd_entry_mac = IntToMac(MacToInt(ARP_SRC_MAC) + entry)
        fake_src_addr = generate_global_addr(nd_entry_mac)
        _, _, src_addr_v6, _, _ = ip_and_intf_info
        tgt_addr = increment_ipv6_addr(src_addr_v6)
        er_pkt = testutils.simple_icmpv6_packet(eth_dst=dut_mac,
                                                eth_src=nd_entry_mac,
                                                ipv6_src=fake_src_addr,
                                                ipv6_dst=tgt_addr,
                                                icmp_type=128,
                                                )
        identifier = random.randint(10000, 50000)
        er_pkt.load = identifier.to_bytes(2, "big") + b"D" * 40
        testutils.send_packet(ptfadapter, ptf_intf_index, er_pkt)


def test_ipv6_nd_incomplete(duthost, ptfhost, config_facts, tbinfo, ip_and_intf_info,
                            ptfadapter, get_function_completeness_level, proxy_arp_enabled,
                            skip_traffic_test):    # noqa F811
    _, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_ipv6_addr = increment_ipv6_addr(ptf_intf_ipv6_addr)
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')
    pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    ipv6_available = get_crm_resources(duthost, "ipv6_neighbor", "available")
    fdb_available = get_crm_resources(duthost, "fdb_entry", "available")
    pytest_assert(ipv6_available > 0 and fdb_available > 0, "Entries have been filled")

    nd_available = min(min(ipv6_available, fdb_available), ENTRIES_NUMBERS)
    tgt_incomplete_neighbor_cnt = min(nd_available, TEST_INCOMPLETE_NEIGHBOR_CNT)

    max_conntrack = int(duthost.command("cat /proc/sys/net/netfilter/nf_conntrack_max")["stdout"])
    logger.info("nf_conntrack_max: {}".format(max_conntrack))
    # since we expect some echo requests packets to miss or overlap,
    # we send slightly more than the maximum
    tgt_conntrack_cnt = int(max_conntrack * 1.1)

    conntrack_cnt = int(duthost.command("cat /proc/sys/net/netfilter/nf_conntrack_count")["stdout"])
    logger.info("nf_conntrack_count pre test: {}".format(conntrack_cnt))

    pytest_assert("[UNREPLIED]" not in duthost.command("sudo conntrack -f ipv6 -L dying")["stdout"],
                  "unreplied icmpv6 requests ended up in the dying list before test is run")

    orig_conntrack_icmpv6_timeout = int(duthost.command("cat /proc/sys/net/netfilter/"
                                                        "nf_conntrack_icmpv6_timeout")["stdout"])
    logger.info("original nf_conntrack_icmpv6_timeout: {}".format(orig_conntrack_icmpv6_timeout))

    try:
        duthost.shell("echo {} > /proc/sys/net/netfilter/nf_conntrack_icmpv6_timeout"
                      .format(TEST_CONNTRACK_TIMEOUT))
        logger.info("setting nf_conntrack_icmpv6_timeout to {}".format(TEST_CONNTRACK_TIMEOUT))

        stop_event = threading.Event()
        thread = InterruptableThread(
            target=add_nd_nonstop,
            args=(ptfadapter, ip_and_intf_info, ptf_intf_index, tgt_incomplete_neighbor_cnt, stop_event),
        )
        thread.daemon = True
        thread.start()
        logger.info("started process to keep sending neighbour-solicitation from ptf to dut")
        time.sleep(3)  # wait for incomplete state entry to accumulate

        send_ipv6_echo_request(ptfadapter, duthost.facts["router_mac"], ip_and_intf_info,
                               ptf_intf_index, tgt_incomplete_neighbor_cnt, tgt_conntrack_cnt)

        conntrack_cnt = int(duthost.command("cat /proc/sys/net/netfilter/nf_conntrack_count")["stdout"])
        logger.info("nf_conntrack_count post test: {}".format(conntrack_cnt))

        pytest_assert("[UNREPLIED]" not in duthost.command("conntrack -f ipv6 -L dying")["stdout"],
                      "unreplied icmpv6 requests ended up in the dying list")

        logger.info("neighbors in INCOMPLETE state: {}"
                    .format(duthost.command("ip -6 neigh")["stdout"].count("INCOMPLETE")))

    finally:
        stop_event.set()
        if thread.is_alive():
            thread.join(timeout=5)
        logger.info("stopped process to keep sending neighbour-solicitation from ptf to dut")

        duthost.command("echo {} > /proc/sys/net/netfilter/nf_conntrack_icmpv6_timeout"
                        .format(orig_conntrack_icmpv6_timeout))
        logger.info("setting nf_conntrack_icmpv6_timeout back to {}".format(orig_conntrack_icmpv6_timeout))
        clear_dut_arp_cache(duthost)
