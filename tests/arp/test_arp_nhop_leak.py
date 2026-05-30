import json
import ptf.testutils as testutils
import pytest
import time
from ipaddress import ip_interface, IPv4Interface
from common.helpers.assertions import pytest_assert

NEIGH_IP = '1.2.3.4'

pytestmark = [
    pytest.mark.topology('t0')
]


@pytest.fixture
def dut_mac(duthost, enum_frontend_asic_index):
    return duthost.asic_instance(enum_frontend_asic_index).get_router_mac()


@pytest.fixture
def nhop_leak_setup(duthost, config_facts):
    vlan_name = list(config_facts['VLAN_INTERFACE'].keys())[0]
    duthost.shell('sonic-clear arp; sonic-clear fdb all')

    # non-dual TOR devices will ignore gratuitous ARP replies,
    # we need to ping the neighbor IP to add it to the ARP table
    duthost.shell('ping -I {} -c1 -W1 {}'.format(vlan_name, NEIGH_IP), module_ignore_errors=True)

    yield

    duthost.shell('sonic-clear arp; sonic-clear fdb all')


@pytest.fixture
def vlan_interface_ip(config_facts):
    vlan_addrs = list(list(config_facts['VLAN_INTERFACE'].items())[0][1].keys())

    for addr in vlan_addrs:
        try:
            if type(ip_interface(addr)) is IPv4Interface:
                return ip_interface(addr)
        except ValueError:
            continue
    return None


@pytest.fixture
def nhop_leak_arp_packets(vlan_interface_ip, dut_mac):
    unlearned_mac = "11:11:11:11:11:11"
    test_mac = "22:22:22:22:22:22"

    # leave the packet src mac as default to ensure that the target mac is not learned on the TOR
    arp_unlearned_mac = testutils.simple_arp_packet(
        eth_dst=dut_mac,
        ip_snd=NEIGH_IP,
        ip_tgt=vlan_interface_ip.ip,
        arp_op=2,
        hw_snd=unlearned_mac
    )

    # explicitly set the packet src mac to ensure that the target mac is learned on the TOR
    arp_learned_mac = testutils.simple_arp_packet(
        eth_dst=dut_mac,
        eth_src=test_mac,
        ip_snd=NEIGH_IP,
        ip_tgt=vlan_interface_ip.ip,
        arp_op=2,
        hw_snd=test_mac
    )
    return arp_unlearned_mac, arp_learned_mac


@pytest.fixture
def generic_ip_packets(dut_mac, vlan_interface_ip):
    dummy_ip = '192.168.0.200'
    pkts = []
    for i in range(0, 256):
        for j in range(0, 256):
            src_mac = f'00:11:22:33:{i:02x}:{j:02x}'
            pkt = testutils.simple_ip_packet(
                eth_dst=dut_mac,
                eth_src=src_mac,
                ip_src=dummy_ip,
                ip_dst=vlan_interface_ip.ip
            )
            pkts.append(pkt)
    return pkts


def get_crm_nexthop_stats(duthost):
    stats = json.loads(duthost.shell('sonic-db-cli COUNTERS_DB hgetall "CRM:STATS"')['stdout'].replace("'", '"'))
    return int(stats['crm_stats_ipv4_nexthop_used']), int(stats['crm_stats_ipv4_nexthop_available'])


def test_arp_nhop_leak(duthost, ptfadapter, intfs_for_test, nhop_leak_setup, nhop_leak_arp_packets, generic_ip_packets):
    """
    Test the scenario where a neighbor update followed by a MAC move can cause a nexthop resource leak in the ASIC
    """
    intf1, intf2, intf1_index, intf2_index = intfs_for_test
    arp1, arp2 = nhop_leak_arp_packets
    pkts_to_send = [arp1] + generic_ip_packets + [arp2]

    nh_used, nh_available = get_crm_nexthop_stats(duthost)
    expected_nh_used = nh_used + 1
    expected_nh_available = nh_available - 1

    for pkt in pkts_to_send:
        testutils.send_packet(ptfadapter, intf1_index, pkt)

    time.sleep(5)  # wait for FDB processing to finish
    post_nh_used, post_nh_available = get_crm_nexthop_stats(duthost)
    pytest_assert(post_nh_used == expected_nh_used,
                  "Expected {} nexthops used, got {}".format(expected_nh_used, post_nh_used))
    pytest_assert(post_nh_available == expected_nh_available,
                  "Expected {} nexthops available, got {}".format(expected_nh_available, post_nh_available))
