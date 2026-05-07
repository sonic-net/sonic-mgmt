"""
This module tests extended ARP features including gratuitous ARP and proxy ARP
"""
import logging
import time
import ptf.testutils as testutils
import pytest

from ipaddress import ip_network
from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr
from tests.arp.arp_utils import clear_dut_arp_cache
from tests.common.helpers.constants import PTF_TIMEOUT
from tests.common.utilities import increment_ipv4_addr, wait_until
from tests.common.helpers.assertions import pytest_assert, pytest_require

pytestmark = [
    pytest.mark.topology('t0', 'dualtor')
]

logger = logging.getLogger(__name__)


def _check_neighbor_entry(duthost, ip, version):
    """Return True if ip is present in the DUT's ARP/neighbor table."""
    switch_arptable = duthost.switch_arptable()['ansible_facts']
    return ip in switch_arptable['arptable'][version]


def test_arp_accept_value(rand_selected_dut, garp_enabled, config_facts):
    """
    Verify that arp_accept is set to 2 when grat_arp is enabled.

    The garp_enabled fixture enables grat_arp in CONFIG_DB. This test verifies
    that the kernel arp_accept sysctl is programmed to 2 (same-subnet only).
    """
    duthost = rand_selected_dut

    vlan_intfs = list(config_facts['VLAN_INTERFACE'].keys())

    for vlan in vlan_intfs:
        arp_accept_res = duthost.shell('cat /proc/sys/net/ipv4/conf/{}/arp_accept'.format(vlan))
        pytest_assert(int(arp_accept_res['stdout']) == 2,
                      "Expected arp_accept=2 for {}, got {}".format(vlan, arp_accept_res['stdout']))


def test_accept_untracked_na_value(rand_selected_dut, garp_enabled, config_facts):
    """
    Verify that accept_untracked_na is set to 2 when grat_arp is enabled.

    The garp_enabled fixture enables grat_arp in CONFIG_DB. This test verifies
    that the kernel accept_untracked_na sysctl (IPv6) is programmed to 2
    (same-subnet only).
    """
    duthost = rand_selected_dut

    vlan_intfs = list(config_facts['VLAN_INTERFACE'].keys())

    for vlan in vlan_intfs:
        accept_untracked_na_res = duthost.shell('cat /proc/sys/net/ipv6/conf/{}/accept_untracked_na'.format(vlan))
        pytest_assert(int(accept_untracked_na_res['stdout']) == 2,
                      "Expected accept_untracked_na=2 for {}, got {}".format(
                          vlan, accept_untracked_na_res['stdout']))


def test_arp_garp_enabled(rand_selected_dut, garp_enabled, ip_and_intf_info, intfs_for_test, config_facts, ptfadapter):
    """
    Send a gratuitous ARP (GARP) packet from the PTF to the DUT

    The DUT should learn the (previously unseen) ARP info from the packet
    """
    pytest_require(garp_enabled, 'Gratuitous ARP not enabled for this device')
    duthost = rand_selected_dut
    ptf_intf_ipv4_addr = ip_and_intf_info[0]

    arp_request_ip = increment_ipv4_addr(ptf_intf_ipv4_addr)
    arp_src_mac = '00:00:07:08:09:0a'
    _, _, intf1_index, _, = intfs_for_test

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

    clear_dut_arp_cache(duthost)

    logger.info("Sending GARP for target {} from PTF interface {}".format(arp_request_ip, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    vlan_intfs = list(config_facts['VLAN_INTERFACE'].keys())

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['macaddress'].lower() == arp_src_mac.lower())
    pytest_assert(switch_arptable['arptable']['v4'][arp_request_ip]['interface'] in vlan_intfs)


def test_arp_garp_out_of_subnet_not_learned(rand_selected_dut, garp_enabled, ip_and_intf_info,
                                            intfs_for_test, config_facts, ptfadapter):
    """
    Send a gratuitous ARP (GARP) packet with a source IP outside the subnet
    of the receiving interface.

    With arp_accept=2, the DUT should NOT learn a neighbor entry from this
    out-of-subnet GARP.
    """
    duthost = rand_selected_dut

    # Derive an out-of-subnet IP from the VLAN's IPv4 subnet
    vlan_addrs = list(list(config_facts['VLAN_INTERFACE'].items())[0][1].keys())
    out_of_subnet_ip = None
    for addr in vlan_addrs:
        try:
            net = ip_network(addr, strict=False)
            if net.version == 4:
                out_of_subnet_ip = str(net.broadcast_address + 10)
                break
        except ValueError:
            continue

    pytest_assert(out_of_subnet_ip is not None, "No IPv4 VLAN subnet found to derive out-of-subnet IP")

    logger.info("VLAN subnet: {}, out-of-subnet IP: {}".format(net, out_of_subnet_ip))
    arp_src_mac = '00:00:07:08:09:0b'
    _, _, intf1_index, _, = intfs_for_test

    pkt = testutils.simple_arp_packet(pktlen=60,
                                      eth_dst='ff:ff:ff:ff:ff:ff',
                                      eth_src=arp_src_mac,
                                      vlan_pcp=0,
                                      arp_op=2,
                                      ip_snd=out_of_subnet_ip,
                                      ip_tgt=out_of_subnet_ip,
                                      hw_snd=arp_src_mac,
                                      hw_tgt='ff:ff:ff:ff:ff:ff'
                                      )

    clear_dut_arp_cache(duthost)

    logger.info("Sending out-of-subnet GARP for target {} from PTF interface {}".format(
        out_of_subnet_ip, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    # Allow time for the DUT to process the packet before verifying it was NOT learned
    time.sleep(5)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(out_of_subnet_ip not in switch_arptable['arptable']['v4'],
                  "Out-of-subnet GARP source {} should NOT be learned with arp_accept=2".format(out_of_subnet_ip))


def test_ipv6_unsolicited_na_link_local_accepted(rand_selected_dut, garp_enabled, ip_and_intf_info,
                                                 intfs_for_test, config_facts, ptfadapter):
    """
    Send an unsolicited IPv6 Neighbor Advertisement (NA) with a link-local
    source address (fe80::).

    Link-local neighbors should still be accepted regardless of arp_accept
    settings, since link-local is always valid on any interface.
    """
    duthost = rand_selected_dut
    ptf_intf_ipv6_addr = ip_and_intf_info[2]
    pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    link_local_ip = 'fe80::100:1'
    na_src_mac = '00:00:07:08:09:0c'
    _, _, intf1_index, _, = intfs_for_test

    # Construct unsolicited NA with link-local source
    pkt = Ether(src=na_src_mac, dst='33:33:00:00:00:01')
    pkt /= IPv6(src=link_local_ip, dst='ff02::1')
    pkt /= ICMPv6ND_NA(tgt=link_local_ip, R=0, S=0, O=1)
    pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=na_src_mac)

    clear_dut_arp_cache(duthost, is_ipv6=True)

    logger.info("Sending link-local unsolicited NA for target {} from PTF interface {}".format(
        link_local_ip, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    pytest_assert(wait_until(5, 1, 0, _check_neighbor_entry, duthost, link_local_ip, 'v6'),
                  "Link-local unsolicited NA source {} should be learned".format(link_local_ip))


def test_ipv6_unsolicited_na_in_subnet_learned(rand_selected_dut, garp_enabled, ip_and_intf_info,
                                               intfs_for_test, config_facts, ptfadapter):
    """
    Send an unsolicited IPv6 Neighbor Advertisement (NA) with a source address
    inside the VLAN's IPv6 subnet.

    The DUT should learn a neighbor entry from this in-subnet unsolicited NA.
    """
    duthost = rand_selected_dut
    ptf_intf_ipv6_addr = ip_and_intf_info[2]
    pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    # Use the in-subnet IPv6 address from ip_and_intf_info (offset by 3 from network address)
    in_subnet_ipv6 = str(ptf_intf_ipv6_addr)
    na_src_mac = '00:00:07:08:09:0e'
    _, _, intf1_index, _, = intfs_for_test

    # Construct unsolicited NA with in-subnet source
    pkt = Ether(src=na_src_mac, dst='33:33:00:00:00:01')
    pkt /= IPv6(src=in_subnet_ipv6, dst='ff02::1')
    pkt /= ICMPv6ND_NA(tgt=in_subnet_ipv6, R=0, S=0, O=1)
    pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=na_src_mac)

    clear_dut_arp_cache(duthost, is_ipv6=True)

    logger.info("Sending in-subnet unsolicited NA for target {} from PTF interface {}".format(
        in_subnet_ipv6, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    pytest_assert(wait_until(5, 1, 0, _check_neighbor_entry, duthost, in_subnet_ipv6, 'v6'),
                  "In-subnet unsolicited NA source {} should be learned".format(in_subnet_ipv6))

    vlan_intfs = list(config_facts['VLAN_INTERFACE'].keys())
    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(switch_arptable['arptable']['v6'][in_subnet_ipv6]['macaddress'].lower() == na_src_mac.lower())
    pytest_assert(switch_arptable['arptable']['v6'][in_subnet_ipv6]['interface'] in vlan_intfs)


def test_ipv6_unsolicited_na_out_of_subnet_not_learned(rand_selected_dut, garp_enabled, ip_and_intf_info,
                                                       intfs_for_test, config_facts, ptfadapter):
    """
    Send an unsolicited IPv6 Neighbor Advertisement (NA) with a source address
    outside the VLAN's IPv6 subnet.

    The DUT should NOT learn a neighbor entry from this out-of-subnet
    unsolicited NA.
    """
    duthost = rand_selected_dut
    ptf_intf_ipv6_addr = ip_and_intf_info[2]
    pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    # Derive an out-of-subnet IPv6 address from the VLAN's IPv6 subnet
    vlan_addrs = list(list(config_facts['VLAN_INTERFACE'].items())[0][1].keys())
    out_of_subnet_ipv6 = None
    for addr in vlan_addrs:
        try:
            net = ip_network(addr, strict=False)
            if net.version == 6:
                # Use an address well beyond the subnet's range
                out_of_subnet_ipv6 = str(net.broadcast_address + 10)
                break
        except ValueError:
            continue

    pytest_assert(out_of_subnet_ipv6 is not None,
                  "No IPv6 VLAN subnet found to derive out-of-subnet address")

    na_src_mac = '00:00:07:08:09:0d'
    _, _, intf1_index, _, = intfs_for_test

    # Construct unsolicited NA: sent to all-nodes multicast, override flag set
    pkt = Ether(src=na_src_mac, dst='33:33:00:00:00:01')
    pkt /= IPv6(src=out_of_subnet_ipv6, dst='ff02::1')
    pkt /= ICMPv6ND_NA(tgt=out_of_subnet_ipv6, R=0, S=0, O=1)
    pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=na_src_mac)

    clear_dut_arp_cache(duthost, is_ipv6=True)

    logger.info("Sending out-of-subnet unsolicited NA for target {} from PTF interface {}".format(
        out_of_subnet_ipv6, intf1_index))
    testutils.send_packet(ptfadapter, intf1_index, pkt)

    # Allow time for the DUT to process the packet before verifying it was NOT learned
    time.sleep(5)

    switch_arptable = duthost.switch_arptable()['ansible_facts']
    pytest_assert(out_of_subnet_ipv6 not in switch_arptable['arptable']['v6'],
                  "Out-of-subnet unsolicited NA source {} should NOT be learned".format(out_of_subnet_ipv6))


def test_proxy_arp(rand_selected_dut, proxy_arp_enabled, ip_and_intf_info, ptfadapter, packets_for_test):
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address within the subnet of the DUT's VLAN.

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC
    """
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info

    ip_version, outgoing_packet, expected_packet = packets_for_test

    if ip_version == "v6" and rand_selected_dut.facts["asic_type"] == "vs":
        pytest.skip("Temporarily skipped to let the sonic-swss submodule be updated.")

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')

    ptfadapter.dataplane.flush()

    if ip_version == 'v6':
        running_config = rand_selected_dut.get_running_config_facts()
        logger.debug("NDP Debug Logs Start")
        for table_name, table in running_config.items():
            if "VLAN" in table_name:
                logger.debug("{}: {}".format(table_name, table))
        swss_status = rand_selected_dut.shell('docker exec swss supervisorctl status',
                                              module_ignore_errors=True)['stdout']
        logger.debug(swss_status)
        ndppd_conf = rand_selected_dut.shell('docker exec swss cat /etc/ndppd.conf',
                                             module_ignore_errors=True)['stdout']
        logger.debug(ndppd_conf)
        # when there are a large number of routes, ndppd will take long time to read /proc/net/ipv6_route.
        # instead of sleep for a specific time, we just log the time taken to read the file to match the delay time.
        # once ndppd performance is improved, this can be removed.
        ipv6_routes_read_time = rand_selected_dut.shell("docker exec swss bash -c 'time wc -l /proc/net/ipv6_route'")
        logger.debug("Total ipv6 route entries: {} \n Read time:{}".format(ipv6_routes_read_time['stdout'],
                                                                           ipv6_routes_read_time['stderr']))

        neigh_table = rand_selected_dut.shell('ip -6 neigh')['stdout']
        logger.debug(neigh_table)

    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    if ip_version == 'v6':
        neigh_table = rand_selected_dut.shell('ip -6 neigh')['stdout']
        logger.debug(neigh_table)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=PTF_TIMEOUT)
