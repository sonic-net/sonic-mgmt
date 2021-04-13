"""
1. Send IPinIP packets from t1 to ToR.
2. Check that for inner packet that has destination IP as active server IP, the packet
is decapsulated and forwarded to server port.
3. Check that for inner packet that has destination IP as standby server IP, the packet
is not forwarded to server port or re-encapsulated to T1s.
"""
import logging
import pytest
import random
import time

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import rand_selected_interface
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.utilities import is_ipv4_address
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import run_garp_service
from tests.common.fixtures.ptfhost_utils import change_mac_addresses

pytestmark = [
    pytest.mark.topology("t0")
]


@pytest.fixture(scope="module", autouse=True)
def mock_common_setup_teardown(
    apply_mock_dual_tor_tables,
    apply_mock_dual_tor_kernel_configs,
    cleanup_mocked_configs,
    request
):
    request.getfixturevalue("run_garp_service")


@pytest.fixture(scope="function")
def build_encapsulated_packet(rand_selected_interface, ptfadapter, rand_selected_dut, tunnel_traffic_monitor):
    """Build the encapsulated packet sent from T1 to ToR."""
    tor = rand_selected_dut
    _, server_ips = rand_selected_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()
    try:
        peer_ipv4_address = [_["address_ipv4"] for _ in config_facts["PEER_SWITCH"].values()][0]
    except IndexError:
        raise ValueError("Failed to get peer ToR address from CONFIG_DB")

    tor_ipv4_address = [_ for _ in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]
                        if is_ipv4_address(_.split("/")[0])][0]
    tor_ipv4_address = tor_ipv4_address.split("/")[0]

    inner_dscp = random.choice(range(0, 33))
    inner_ttl = random.choice(range(3, 65))
    inner_packet = testutils.simple_ip_packet(
        ip_src="1.1.1.1",
        ip_dst=server_ipv4,
        ip_dscp=inner_dscp,
        ip_ttl=inner_ttl
    )[IP]
    packet = testutils.simple_ipv4ip_packet(
        eth_dst=tor.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, 0),
        ip_src=peer_ipv4_address,
        ip_dst=tor_ipv4_address,
        ip_dscp=inner_dscp,
        ip_ttl=255,
        inner_frame=inner_packet
    )
    logging.info("the encapsulated packet to send:\n%s", tunnel_traffic_monitor._dump_show_str(packet))
    return packet


def get_ptf_server_intf_index(tor, tbinfo, iface):
    """Get the index of ptf ToR-facing interface on ptf."""
    mg_facts = tor.get_extended_minigraph_facts(tbinfo)
    return mg_facts["minigraph_ptf_indices"][iface]


def build_expected_packet_to_server(encapsulated_packet):
    """Build packet expected to be received by server from the tunnel packet."""
    inner_packet = encapsulated_packet[IP].payload[IP].copy()
    # use dummy mac address that will be ignored in mask
    inner_packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff") / inner_packet
    exp_pkt = mask.Mask(inner_packet)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IP, "tos")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")
    return exp_pkt


def test_decap_active_tor(
    apply_active_state_to_orchagent,
    build_encapsulated_packet,
    rand_selected_interface, ptfadapter,
    tbinfo, rand_selected_dut, tunnel_traffic_monitor
):
    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    ptfadapter.dataplane.flush()
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
    testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=10)
    _, rec_pkt = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[exp_ptf_port_index])
    rec_pkt = Ether(rec_pkt)
    logging.info("received decap packet:\n%s", tunnel_traffic_monitor._dump_show_str(rec_pkt))
    exp_ttl = encapsulated_packet[IP].payload[IP].ttl - 1
    exp_tos = encapsulated_packet[IP].payload[IP].tos
    if rec_pkt[IP].ttl != exp_ttl:
        pytest.fail("the expected ttl should be %s" % exp_ttl)
    if rec_pkt[IP].tos != exp_tos:
        pytest.fail("the expected tos should be %s" % exp_tos)


def test_decap_standby_tor(
    apply_standby_state_to_orchagent,
    build_encapsulated_packet,
    rand_selected_interface, ptfadapter,
    tbinfo, rand_selected_dut, tunnel_traffic_monitor
):

    def verify_downstream_packet_to_server(ptfadapter, port, exp_pkt):
        """Verify packet is passed downstream to server."""
        packets = ptfadapter.dataplane.packet_queues[(0, port)]
        for packet in packets:
            if exp_pkt.pkt_match(packet):
                return True
        return False

    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
    with tunnel_traffic_monitor(tor, existing=False):
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=10)
        time.sleep(2)
        verify_downstream_packet_to_server(ptfadapter, exp_ptf_port_index, exp_pkt)
