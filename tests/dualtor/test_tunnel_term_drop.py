"""
Test tunnel termination drop on dualtor.

When a ToR is in standby mode, IPinIP tunneled traffic arriving from the peer
ToR should be dropped - not forwarded to the server port and not
re-encapsulated back to T1. This prevents traffic looping between two standby
ToRs.

Related issue: https://github.com/sonic-net/sonic-mgmt/issues/21092
"""
import json
import logging
import random

import pytest
from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP

from tests.common.dualtor.dual_tor_common import (  # noqa: F401
    active_active_ports,
    active_standby_ports,
    cable_type,
    CableType
)
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_pc_ports
from tests.common.dualtor.dual_tor_utils import get_ptf_server_intf_index
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.tunnel_traffic_utils import (  # noqa: F401
    tunnel_traffic_monitor
)
from tests.common.utilities import is_ipv4_address
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require

pytestmark = [
    pytest.mark.topology("dualtor")
]

logger = logging.getLogger(__name__)
PACKET_COUNT = 1000
# Allow a 10% tolerance so the test is not flaky on a few PTF tx losses or
# counter-read timing skew.
COUNTER_RX_OK_THRESHOLD = int(PACKET_COUNT * 0.9)
COUNTER_NO_TRAFFIC_THRESHOLD = int(PACKET_COUNT * 0.1)
COUNTER_CHECK_TIMEOUT = 15
COUNTER_CHECK_INTERVAL = 5


def _ptf_intf_to_port_index(ptf_intf):
    """Convert a PTF interface name such as eth0 to a PTF port index."""
    pytest_assert(
        ptf_intf.startswith("eth"),
        "Unexpected PTF interface name {}".format(ptf_intf)
    )
    return int(ptf_intf[len("eth"):])


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
    peer_switch = peer_switches[0]
    pytest_assert(
        "address_ipv4" in peer_switch,
        "Failed to get peer ToR IPv4 address from CONFIG_DB"
    )
    peer_ipv4_address = peer_switch["address_ipv4"]

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
    # tos is a don't-care: this is a negative check (the packet must NOT
    # appear), so widening the mask avoids a false pass where the ToR did
    # wrongly forward the packet but rewrote ToS/DSCP so it failed to match.
    exp_pkt.set_do_not_care_scapy(IP, "tos")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    return exp_pkt


def _get_dut_intf_for_ptf_port(tor, tbinfo, ptf_port):
    """Get DUT interface name connected to the given PTF port."""
    ptf_port_index = _ptf_intf_to_port_index(ptf_port)
    mg_facts = tor.get_extended_minigraph_facts(tbinfo)
    for intf, index in mg_facts["minigraph_ptf_indices"].items():
        if index == ptf_port_index:
            return intf
    raise ValueError(
        "Failed to find DUT interface for PTF port {}".format(ptf_port)
    )


def _get_all_t1_dut_intfs(tor, tbinfo):
    """Get all DUT-side interface names facing T1 (every portchannel member).

    The packet-level re-encapsulation check in ``tunnel_traffic_monitor``
    listens on every T1 PTF port, but it is skipped on VS/KVM platforms. On
    those platforms the port-counter check below becomes the only guard
    against the loop-prevention path, so it must mirror the same port set:
    a wrongly re-encapsulated packet can egress on any T1 member port, not
    just the one the test injected on.
    """
    pc_ports = get_t1_ptf_pc_ports(tor, tbinfo)
    ptf_intfs = [intf for intfs in pc_ports.values() for intf in intfs]
    return sorted(
        {_get_dut_intf_for_ptf_port(tor, tbinfo, ptf_intf)
         for ptf_intf in ptf_intfs}
    )


def _parse_counter(counter):
    """Parse a SONiC counter value such as '1,000' into an integer."""
    return int(str(counter).replace(",", ""))


def _get_and_log_port_counters(tor, interfaces):
    """Get and log selected port counters for traffic drop debugging."""
    counters = json.loads(tor.get_port_counters(in_json=True))
    missing_interfaces = [
        intf for intf in interfaces
        if intf not in counters
    ]
    pytest_assert(
        not missing_interfaces,
        "Missing port counters for {}".format(missing_interfaces)
    )
    selected_counters = {
        intf: counters[intf] for intf in interfaces
    }
    logger.info(
        "Port counters on %s:\n%s",
        tor.hostname,
        json.dumps(selected_counters, indent=4)
    )
    return selected_counters


def _check_drop_counters(tor, server_intf, ingress_t1_intf, all_t1_intfs):
    """Check that packet counters match tunnel drop expectations.

    Expectations after sending PACKET_COUNT tunnel packets to a standby ToR:
      - ingress T1 port RX_OK is at least 90% of what we sent (the packets
        did arrive on the DUT),
      - the server-facing port TX_OK stays under the no-traffic threshold
        (not decapsulated and forwarded down to the server),
      - EVERY T1-facing port TX_OK stays under the no-traffic threshold (not
        re-encapsulated back toward T1 on any port -- a wrongly re-encapped
        packet could egress on a different T1 member than the ingress one).
    """
    interfaces = sorted(set(all_t1_intfs) | {server_intf, ingress_t1_intf})

    def _check_counters():
        counters = _get_and_log_port_counters(tor, interfaces)
        server_tx_ok = _parse_counter(counters[server_intf]["TX_OK"])
        ingress_t1_rx_ok = _parse_counter(counters[ingress_t1_intf]["RX_OK"])
        t1_tx_ok = {
            intf: _parse_counter(counters[intf]["TX_OK"])
            for intf in all_t1_intfs
        }
        max_t1_tx_intf = max(t1_tx_ok, key=t1_tx_ok.get)
        max_t1_tx_ok = t1_tx_ok[max_t1_tx_intf]

        logger.info(
            "Counter expectation after sending %d packets: "
            "%s RX_OK >= %d, %s TX_OK < %d, all T1 TX_OK < %d. "
            "Current values: %s RX_OK=%d, %s TX_OK=%d, "
            "max T1 TX_OK=%d on %s",
            PACKET_COUNT,
            ingress_t1_intf,
            COUNTER_RX_OK_THRESHOLD,
            server_intf,
            COUNTER_NO_TRAFFIC_THRESHOLD,
            COUNTER_NO_TRAFFIC_THRESHOLD,
            ingress_t1_intf,
            ingress_t1_rx_ok,
            server_intf,
            server_tx_ok,
            max_t1_tx_ok,
            max_t1_tx_intf
        )
        return (
            ingress_t1_rx_ok >= COUNTER_RX_OK_THRESHOLD and
            server_tx_ok < COUNTER_NO_TRAFFIC_THRESHOLD and
            max_t1_tx_ok < COUNTER_NO_TRAFFIC_THRESHOLD
        )

    pytest_assert(
        wait_until(
            COUNTER_CHECK_TIMEOUT,
            COUNTER_CHECK_INTERVAL,
            0,
            _check_counters
        ),
        "Port counters do not match tunnel drop expectations"
    )


@pytest.mark.enable_active_active
@pytest.mark.dualtor_active_standby_toggle_to_random_unselected_tor
@pytest.mark.dualtor_active_active_setup_standby_on_random_tor
def test_tunnel_term_drop_standby(
    build_encapsulated_ip_packet,
    rand_selected_mux_interface, ptfadapter,                # noqa: F811
    tbinfo, rand_selected_dut, setup_dualtor_mux_ports,     # noqa: F811
    tunnel_traffic_monitor                                  # noqa: F811
):
    """
    Verify that a standby ToR drops IPinIP tunnel traffic from the peer ToR.

    The standard dualtor mux setup markers put the selected DUT into standby.
    The test then injects the receiving side of the both-standby loop scenario:
    the selected standby ToR receives an IPinIP packet that would have been
    generated by the peer ToR. If the selected ToR does not drop this tunnel
    packet, it can decapsulate it to the server or re-encapsulate it toward T1
    and create a loop.

    The packet must NOT be:
      - Decapsulated and forwarded to the server port
      - Re-encapsulated and sent back to T1 (which would cause a loop)
    """
    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_ip_packet
    iface, _ = rand_selected_mux_interface
    pytest_assert(setup_dualtor_mux_ports, "Failed to set up dualtor mux ports")
    logger.info(
        "Using %s as standby tunnel receiver on mux interface %s",
        tor.hostname,
        iface
    )

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = _build_expected_server_packet(encapsulated_packet)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logger.info(
        "Sending encapsulated packet from PTF T1 interface %s", ptf_t1_intf
    )
    t1_dut_intf = _get_dut_intf_for_ptf_port(tor, tbinfo, ptf_t1_intf)
    all_t1_dut_intfs = _get_all_t1_dut_intfs(tor, tbinfo)

    # tunnel_traffic_monitor with existing=False asserts that the receiving
    # standby ToR does not re-encapsulate the packet back toward T1.
    with tunnel_traffic_monitor(tor, existing=False):
        logger.info("Clear port counters on %s", tor.hostname)
        tor.command("sonic-clear counters")
        ptfadapter.dataplane.flush()
        testutils.send(
            ptfadapter,
            _ptf_intf_to_port_index(ptf_t1_intf),
            encapsulated_packet,
            count=PACKET_COUNT
        )
        # Verify the packet is NOT forwarded to the server port
        testutils.verify_no_packet(
            ptfadapter, exp_pkt, exp_ptf_port_index, timeout=5
        )
    _check_drop_counters(tor, iface, t1_dut_intf, all_t1_dut_intfs)
    logger.info("Verified: standby ToR dropped tunnel traffic as expected")
