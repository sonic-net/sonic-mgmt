
import pytest
import ptf.testutils as testutils

import time
import itertools
import logging
import pprint

from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('t0')
]

DEFAULT_FDB_ETHERNET_TYPE = 0x1234
DUMMY_MAC_PREFIX = "02:11:22:33"
DUMMY_MAC_COUNT = 10
FDB_POPULATE_SLEEP_TIMEOUT = 2
FDB_WAIT_EXPECTED_PACKET_TIMEOUT = 5
PKT_TYPES = ["ethernet", "arp_request", "arp_reply"]

logger = logging.getLogger(__name__)

def send_eth(ptfadapter, source_port, source_mac, dest_mac):
    """
    send ethernet packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :return:
    """
    pkt = testutils.simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        eth_type=DEFAULT_FDB_ETHERNET_TYPE
    )
    logger.debug('send packet source port id {} smac: {} dmac: {}'.format(source_port, source_mac, dest_mac))
    testutils.send(ptfadapter, source_port, pkt)


def send_arp_request(ptfadapter, source_port, source_mac, dest_mac):
    """
    send arp request packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :return:
    """
    pkt = testutils.simple_arp_packet(pktlen=60,
                eth_dst='ff:ff:ff:ff:ff:ff',
                eth_src=source_mac,
                vlan_vid=0,
                vlan_pcp=0,
                arp_op=1,
                ip_snd='10.10.1.3',
                ip_tgt='10.10.1.2',
                hw_snd=source_mac,
                hw_tgt='ff:ff:ff:ff:ff:ff',
                )
    logger.debug('send ARP request packet source port id {} smac: {} dmac: {}'.format(source_port, source_mac, dest_mac))
    testutils.send(ptfadapter, source_port, pkt)


def send_arp_reply(ptfadapter, source_port, source_mac, dest_mac):
    """
    send arp reply packet
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_mac: destination MAC
    :return:
    """
    pkt = testutils.simple_arp_packet(eth_dst=dest_mac,
                eth_src=source_mac,
                arp_op=2,
                ip_snd='10.10.1.2',
                ip_tgt='10.10.1.3',
                hw_tgt=dest_mac,
                hw_snd=source_mac,
                )
    logger.debug('send ARP reply packet source port id {} smac: {} dmac: {}'.format(source_port, source_mac, dest_mac))
    testutils.send(ptfadapter, source_port, pkt)


def send_recv_eth(ptfadapter, source_port, source_mac, dest_port, dest_mac):
    """
    send ethernet packet and verify it on dest_port
    :param ptfadapter: PTF adapter object
    :param source_port: source port
    :param source_mac: source MAC
    :param dest_port: destination port to receive packet on
    :param dest_mac: destination MAC
    :return:
    """
    pkt = testutils.simple_eth_packet(
        eth_dst=dest_mac,
        eth_src=source_mac,
        eth_type=DEFAULT_FDB_ETHERNET_TYPE
    )
    logger.debug('send packet src port {} smac: {} dmac: {} verifying on dst port {}'.format(
        source_port, source_mac, dest_mac, dest_port))
    testutils.send(ptfadapter, source_port, pkt)
    testutils.verify_packet_any_port(ptfadapter, pkt, [dest_port], timeout=FDB_WAIT_EXPECTED_PACKET_TIMEOUT)


def setup_fdb(ptfadapter, vlan_table, router_mac, pkt_type):
    """
    :param ptfadapter: PTF adapter object
    :param vlan_table: VLAN table map: VLAN subnet -> list of VLAN members
    :return: FDB table map : VLAN member -> MAC addresses set
    """

    fdb = {}

    assert pkt_type in PKT_TYPES

    for vlan in vlan_table:
        for member in vlan_table[vlan]:
            mac = ptfadapter.dataplane.get_mac(0, member)
            # send a packet to switch to populate layer 2 table with MAC of PTF interface
            send_eth(ptfadapter, member, mac, router_mac)

            # put in learned MAC
            fdb[member] = { mac }

            # Send packets to switch to populate the layer 2 table with dummy MACs for each port
            # Totally 10 dummy MACs for each port, send 1 packet for each dummy MAC
            dummy_macs = ['{}:{:02x}:{:02x}'.format(DUMMY_MAC_PREFIX, member, i)
                          for i in range(DUMMY_MAC_COUNT)]

            for dummy_mac in dummy_macs:
                if pkt_type == "ethernet":
                    send_eth(ptfadapter, member, dummy_mac, router_mac)
                elif pkt_type == "arp_request":
                    send_arp_request(ptfadapter, member, dummy_mac, router_mac)
                elif pkt_type == "arp_reply":
                    send_arp_reply(ptfadapter, member, dummy_mac, router_mac)
                else:
                    pytest.fail("Unknown option '{}'".format(pkt_type))

            # put in set learned dummy MACs
            fdb[member].update(dummy_macs)

    time.sleep(FDB_POPULATE_SLEEP_TIMEOUT)

    return fdb


@pytest.fixture
def fdb_cleanup(duthost):
    """ cleanup FDB before and after test run """
    try:
        duthost.command('sonic-clear fdb all')
        yield
    finally:
        # in any case clear fdb after test
        duthost.command('sonic-clear fdb all')


@pytest.mark.bsl
@pytest.mark.usefixtures('fdb_cleanup')
@pytest.mark.parametrize("pkt_type", PKT_TYPES)
def test_fdb(ansible_adhoc, testbed, ptfadapter, duthost, ptfhost, pkt_type):
    """
    1. verify fdb forwarding.
    2. verify show mac command on DUT for learned mac.
    """

    host_facts  = duthost.setup()['ansible_facts']
    conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    # reinitialize data plane due to above changes on PTF interfaces
    ptfadapter.reinit()

    router_mac = host_facts['ansible_Ethernet0']['macaddress']

    port_index_to_name = { v: k for k, v in conf_facts['port_index_map'].items() }

    # Only take interfaces that are in ptf topology
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    available_ports_idx = [ idx for idx, name in ptf_ports_available_in_topo.items()
    if conf_facts['PORT'][port_index_to_name[idx]].get('admin_status', 'down') == 'up' ]

    vlan_table = {}

    for name, vlan in conf_facts['VLAN'].items():
        vlan_table[name] = []
        ifnames = conf_facts['VLAN_MEMBER'][name].keys()
        vlan_table[name] = [ conf_facts['port_index_map'][ifname] for ifname in ifnames
        if conf_facts['port_index_map'][ifname] in available_ports_idx ]

    vlan_member_count = sum([ len(members) for name, members in vlan_table.items() ])

    fdb = setup_fdb(ptfadapter, vlan_table, router_mac, pkt_type)
    for vlan in vlan_table:
        for src, dst in itertools.combinations(vlan_table[vlan], 2):
            for src_mac, dst_mac in itertools.product(fdb[src], fdb[dst]):
                send_recv_eth(ptfadapter, src, src_mac, dst, dst_mac)

    # Should we have fdb_facts ansible module for this test?
    res = duthost.command('show mac')
    logger.info('"show mac" output on DUT:\n{}'.format(pprint.pformat(res['stdout_lines'])))

    dummy_mac_count = 0
    total_mac_count = 0
    for l in res['stdout_lines']:
        if DUMMY_MAC_PREFIX in l.lower():
            dummy_mac_count += 1
        if "dynamic" in l.lower():
            total_mac_count += 1

    print res

    assert vlan_member_count > 0

    # Verify that the number of dummy MAC entries is expected
    assert dummy_mac_count == DUMMY_MAC_COUNT * vlan_member_count
