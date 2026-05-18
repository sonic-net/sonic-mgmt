"""
Test tunnel termination drop on dualtor.

When a ToR is in standby mode, IPinIP tunneled traffic arriving from the peer
ToR should be dropped - not forwarded to the server port and not
re-encapsulated back to T1. This prevents traffic looping between two standby
ToRs.

Related issue: https://github.com/sonic-net/sonic-mgmt/issues/21092
"""
import logging
import pytest
import random

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP

from tests.common.dualtor.dual_tor_mock import *  # noqa: F403
from tests.common.dualtor.dual_tor_common import (  # noqa: F401
    active_active_ports,
    active_standby_ports,
    cable_type,
    CableType
)
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import get_ptf_server_intf_index
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import (  # noqa: F401
    setup_standby_ports_on_rand_selected_tor
)
from tests.common.dualtor.mux_simulator_control import (  # noqa: F401
    toggle_all_simulator_ports_to_rand_unselected_tor
)
from tests.common.dualtor.tunnel_traffic_utils import (  # noqa: F401
    tunnel_traffic_monitor
)
from tests.common.fixtures.ptfhost_utils import run_garp_service  # noqa: F401
from tests.common.utilities import is_ipv4_address
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require

pytestmark = [
    pytest.mark.topology("dualtor")
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(
    apply_mock_dual_tor_tables,          # noqa: F811
    apply_mock_dual_tor_kernel_configs,  # noqa: F811
    cleanup_mocked_configs,              # noqa: F811
    request
):
    """Module-level setup for mocked dual ToR tables and kernel configs."""
    request.getfixturevalue("run_garp_service")


@pytest.fixture(scope="function")
def rand_selected_mux_interface(
    rand_selected_dut, cable_type, active_active_ports,       # noqa: F811
    active_standby_ports                                      # noqa: F811
):
    """Select a random mux interface matching the current cable type."""
    mux_ports = (
        active_active_ports if cable_type == CableType.active_active
        else active_standby_ports
    )
    pytest_require(
        mux_ports,
        "No {} mux ports, skip...".format(cable_type)
    )

    tor = rand_selected_dut
    server_ips = mux_cable_server_ip(tor)
    candidate_interfaces = [
        str(iface) for iface in mux_ports
        if str(iface) in server_ips
    ]
    pytest_require(
        candidate_interfaces,
        "No {} mux ports with server IP config, skip...".format(cable_type)
    )

    iface = random.choice(candidate_interfaces)
    logger.info("Select %s DUT interface %s to test.", cable_type, iface)
    return iface, server_ips[iface]


@pytest.fixture(scope="function")
def build_encapsulated_ip_packet(
    rand_selected_mux_interface, ptfadapter, rand_selected_dut
):   # noqa: F811
    """
    Build an IPinIP encapsulated packet as if sent from the peer ToR.

    Outer: src=peer_loopback, dst=local_loopback
    Inner: src=1.1.1.1, dst=server_ip
    """
    tor = rand_selected_dut
    _, server_ips = rand_selected_mux_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()

    peer_switches = list(config_facts.get("PEER_SWITCH", {}).values())
    pytest_assert(
        peer_switches,
        "Failed to get peer ToR address from CONFIG_DB"
    )
    peer_ipv4_address = peer_switches[0]["address_ipv4"]

    loopback0_addrs = config_facts.get(
        "LOOPBACK_INTERFACE", {}
    ).get("Loopback0", [])
    tor_ipv4_addrs = [
        _ for _ in loopback0_addrs
        if is_ipv4_address(_.split("/")[0])
    ]
    pytest_assert(
        tor_ipv4_addrs,
        "Failed to get local ToR loopback address from CONFIG_DB"
    )
    tor_ipv4_address = tor_ipv4_addrs[0].split("/")[0]

    inner_dscp = random.choice(list(range(0, 33)))
    inner_ttl = random.choice(list(range(3, 65)))
    inner_packet = testutils.simple_ip_packet(
        ip_src="1.1.1.1",
        ip_dst=server_ipv4,
        ip_dscp=inner_dscp,
        ip_ttl=inner_ttl
    )[IP]
    packet = testutils.simple_ipv4ip_packet(
        eth_dst=tor.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(
            *list(ptfadapter.dataplane.ports.keys())[0]
        ),
        ip_src=peer_ipv4_address,
        ip_dst=tor_ipv4_address,
        ip_dscp=inner_dscp,
        ip_ttl=255,
        inner_frame=inner_packet
    )
    logger.info(
        "Built encapsulated packet:\n%s",
        dump_scapy_packet_show_output(packet)
    )
    return packet


def _build_expected_server_packet(encapsulated_packet):
    """Build the expected decapsulated packet that would reach the server."""
    inner_packet = encapsulated_packet[IP].payload[IP].copy()
    inner_packet = Ether(
        src="aa:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff"
    ) / inner_packet
    exp_pkt = mask.Mask(inner_packet)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    return exp_pkt


@pytest.mark.enable_active_active
def test_tunnel_term_drop_standby(
    build_encapsulated_ip_packet, request,
    rand_selected_mux_interface, ptfadapter,                # noqa: F811
    cable_type,                                             # noqa: F811
    tbinfo, rand_selected_dut, tunnel_traffic_monitor       # noqa: F811
):
    """
    Verify that a standby ToR drops IPinIP tunnel traffic from the peer ToR.

    This injects the receiving side of the both-standby loop scenario:
    the local ToR is standby and receives an IPinIP packet that would have been
    generated by the peer ToR. If the local ToR does not drop this tunnel
    packet, it can re-encapsulate traffic back toward T1 and create a loop.

    The packet must NOT be:
      - Decapsulated and forwarded to the server port
      - Re-encapsulated and sent back to T1 (which would cause a loop)
    """
    if cable_type == CableType.active_active:
        request.getfixturevalue("setup_standby_ports_on_rand_selected_tor")
    elif is_t0_mocked_dualtor(tbinfo):  # noqa: F405
        request.getfixturevalue("apply_standby_state_to_orchagent")
    else:
        request.getfixturevalue(
            "toggle_all_simulator_ports_to_rand_unselected_tor"
        )

    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_ip_packet
    iface, _ = rand_selected_mux_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = _build_expected_server_packet(encapsulated_packet)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logger.info(
        "Sending encapsulated packet from PTF T1 interface %s", ptf_t1_intf
    )

    # tunnel_traffic_monitor with existing=False asserts that the receiving
    # standby ToR does not re-encapsulate the packet back toward T1.
    with tunnel_traffic_monitor(tor, existing=False):
        ptfadapter.dataplane.flush()
        testutils.send(
            ptfadapter,
            int(ptf_t1_intf.strip("eth")),
            encapsulated_packet,
            count=10
        )
        # Verify the packet is NOT forwarded to the server port
        testutils.verify_no_packet(
            ptfadapter, exp_pkt, exp_ptf_port_index, timeout=5
        )
    logger.info("Verified: standby ToR dropped tunnel traffic as expected")
