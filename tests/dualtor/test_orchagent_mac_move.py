import logging
import pytest
import random

from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import crm_neighbor_checker
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import run_garp_service
from tests.common.fixtures.ptfhost_utils import change_mac_addresses
from tests.common.utilities import dump_scapy_packet_show_output


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'run_garp_service',
                            'run_icmp_responder')
]


NEW_NEIGHBOR_IPV4_ADDR = "192.168.0.250"
NEW_NEIGHBOR_HWADDR = "02:AA:BB:CC:DD:EE"


@pytest.fixture(scope="function")
def announce_new_neighbor(ptfadapter, rand_selected_dut, tbinfo):
    """Utility fixture to announce new neighbor from a mux port."""

    def _announce_new_neighbor_gen():
        """Generator to announce the neighbor to a different interface at each iteration."""
        for dut_iface in dut_ifaces:
            update_iface_func = yield dut_iface
            if callable(update_iface_func):
                update_iface_func(dut_iface)
            ptf_iface = dut_to_ptf_intf_map[dut_iface]
            garp_packet = testutils.simple_arp_packet(
                eth_src=NEW_NEIGHBOR_HWADDR,
                hw_snd=NEW_NEIGHBOR_HWADDR,
                ip_snd=NEW_NEIGHBOR_IPV4_ADDR,
                ip_tgt=NEW_NEIGHBOR_IPV4_ADDR,
                arp_op=2
            )
            logging.info(
                "GARP packet to announce new neighbor %s to mux interface %s:\n%s",
                NEW_NEIGHBOR_IPV4_ADDR, dut_iface, dump_scapy_packet_show_output(garp_packet)
            )
            testutils.send(ptfadapter, int(ptf_iface), garp_packet, count=5)
            # let the generator stops here to allow the caller to execute testings
            yield

    dut_to_ptf_intf_map = rand_selected_dut.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    mux_configs = mux_cable_server_ip(rand_selected_dut)
    dut_ifaces = mux_configs.keys()
    random.shuffle(dut_ifaces)
    return _announce_new_neighbor_gen()


@pytest.fixture(autouse=True)
def cleanup_arp(duthosts):
    """Cleanup arp entries after test."""
    yield
    for duthost in duthosts:
        duthost.shell("sonic-clear arp")


@pytest.fixture(autouse=True)
def enable_garp(duthost):
    """Enable creating arp table entry for gratuitous ARP."""
    vlan_intf = duthost.get_running_config_facts()["VLAN_MEMBER"].keys()[0]
    cmd = "echo %s > /proc/sys/net/ipv4/conf/" + vlan_intf + "/arp_accept"
    duthost.shell(cmd % 1)
    yield
    duthost.shell(cmd % 0)


def test_mac_move(
    require_mocked_dualtor,
    announce_new_neighbor, apply_active_state_to_orchagent,
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, set_crm_polling_interval,
    tbinfo, tunnel_traffic_monitor, vmhost
):
    tor = rand_selected_dut
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    ptf_t1_intf_index = int(ptf_t1_intf.strip("eth"))

    # new neighbor learnt on an active port
    test_port = next(announce_new_neighbor)
    announce_new_neighbor.send(None)
    logging.info("let new neighbor learnt on active port %s", test_port)
    pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, NEW_NEIGHBOR_IPV4_ADDR)
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=False)
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_port,
        conn_graph_facts, exp_pkt, existing=True, is_mocked=is_mocked_dualtor(tbinfo)
    )
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)

    # mac move to a standby port
    test_port = next(announce_new_neighbor)
    announce_new_neighbor.send(lambda iface: set_dual_tor_state_to_orchagent(tor, "standby", [iface]))
    logging.info("mac move to a standby port %s", test_port)
    pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, NEW_NEIGHBOR_IPV4_ADDR)
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=True)
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_port,
        conn_graph_facts, exp_pkt, existing=False, is_mocked=is_mocked_dualtor(tbinfo)
    )
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)

    # standby forwarding check after fdb ageout/flush
    tor.shell("fdbclear")
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_port,
        conn_graph_facts, exp_pkt, existing=False, is_mocked=is_mocked_dualtor(tbinfo)
    )
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)

    # mac move to another active port
    test_port = next(announce_new_neighbor)
    announce_new_neighbor.send(None)
    logging.info("mac move to another active port %s", test_port)
    pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, NEW_NEIGHBOR_IPV4_ADDR)
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=False)
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_port,
        conn_graph_facts, exp_pkt, existing=True, is_mocked=is_mocked_dualtor(tbinfo)
    )
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)

    # active forwarding check after fdb ageout/flush
    tor.shell("fdbclear")
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_port,
        conn_graph_facts, exp_pkt, existing=False, is_mocked=is_mocked_dualtor(tbinfo)
    )
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)
