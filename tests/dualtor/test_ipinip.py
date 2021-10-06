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
import contextlib

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import rand_selected_interface
from tests.common.dualtor.dual_tor_utils import get_ptf_server_intf_index
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.utilities import is_ipv4_address
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import run_garp_service
from tests.common.fixtures.ptfhost_utils import change_mac_addresses
from tests.common.utilities import dump_scapy_packet_show_output


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
    logging.info("the encapsulated packet to send:\n%s", dump_scapy_packet_show_output(packet))
    return packet


def build_expected_packet_to_server(encapsulated_packet, decrease_ttl=False):
    """Build packet expected to be received by server from the tunnel packet."""
    inner_packet = encapsulated_packet[IP].payload[IP].copy()
    # use dummy mac address that will be ignored in mask
    inner_packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff") / inner_packet
    if decrease_ttl:
        inner_packet.ttl = inner_packet.ttl - 1
    exp_pkt = mask.Mask(inner_packet)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")
    return exp_pkt


def test_decap_active_tor(
    build_encapsulated_packet, request, ptfhost,
    rand_selected_interface, ptfadapter,
    tbinfo, rand_selected_dut, tunnel_traffic_monitor):

    @contextlib.contextmanager
    def stop_garp(ptfhost):
        """Temporarily stop garp service."""
        ptfhost.shell("supervisorctl stop garp_service")
        yield
        ptfhost.shell("supervisorctl start garp_service")

    if is_t0_mocked_dualtor(tbinfo):
        request.getfixturevalue('apply_active_state_to_orchagent')
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_selected_tor')

    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet, decrease_ttl=True)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
    with stop_garp(ptfhost):
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet)
        testutils.verify_packet(ptfadapter, exp_pkt, exp_ptf_port_index, timeout=10)


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
