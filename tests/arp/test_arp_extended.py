"""
This module tests extended ARP features including gratuitous ARP and proxy ARP
"""
import logging
import ptf.testutils as testutils
import pytest

from tests.arp.arp_utils import clear_dut_arp_cache, increment_ipv4_addr
from tests.common.helpers.assertions import pytest_assert, pytest_require

pytestmark = [
    pytest.mark.topology('t0', 'dualtor')
]

logger = logging.getLogger(__name__)


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


def test_proxy_arp(rand_selected_dut, proxy_arp_enabled, ip_and_intf_info, ptfadapter, packets_for_test):
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address within the subnet of the DUT's VLAN.

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC
    """
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs')

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info

    ip_version, outgoing_packet, expected_packet = packets_for_test

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

        neigh_table = rand_selected_dut.shell('ip -6 neigh')['stdout']
        logger.debug(neigh_table)

    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    if ip_version == 'v6':
        neigh_table = rand_selected_dut.shell('ip -6 neigh')['stdout']
        logger.debug(neigh_table)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=10)
