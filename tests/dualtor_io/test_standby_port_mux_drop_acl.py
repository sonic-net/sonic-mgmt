"""
Test to verify that packets dropped by standby port MUX drop ACL
are not counted as RX_DRP in the port counters.

Issue: https://github.com/sonic-net/sonic-mgmt/issues/23182

Test description:
    In a dualtor active-standby setup, when packets arrive at the
    standby ToR's mux port, they are dropped by the MUX drop ACL.
    These ACL-based drops should NOT be reflected in the RX_DRP
    counter on the standby port.

    This test sends packets from PTF (simulating T1 traffic) to a
    server behind a mux port on the standby ToR, and verifies that
    the RX_DRP counter on the standby mux port is not incremented.
"""
import logging
import pytest
import random
import time

from ptf import testutils
from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.dual_tor_common import cable_type                                     # noqa: F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                  # noqa: F401
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service            # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                            # noqa: F401
from tests.common.helpers.drop_counters.drop_counters import get_pkt_drops, GET_L2_COUNTERS, RX_DRP


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("dualtor")
]

PACKETS_TO_SEND = 100
COUNTER_POLL_WAIT = 10


def get_rx_drp_count(duthost, interface):
    """Get the current RX_DRP counter value for a specific interface.

    Args:
        duthost: The DUT host object.
        interface: The interface name (e.g., 'Ethernet0').

    Returns:
        int: The current RX_DRP counter value, or 0 if not available.
    """
    counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
    if interface in counters and RX_DRP in counters[interface]:
        try:
            return int(counters[interface][RX_DRP].replace(",", ""))
        except (ValueError, AttributeError):
            logger.warning("Unable to parse RX_DRP counter for interface %s", interface)
            return 0
    return 0


def test_standby_mux_drop_not_counted_as_rx_drp(
    upper_tor_host, lower_tor_host,                         # noqa: F811
    toggle_all_simulator_ports_to_upper_tor,                # noqa: F811
    ptfadapter, tbinfo, cable_type,                         # noqa: F811
    run_icmp_responder, run_garp_service,                   # noqa: F811
    change_mac_addresses                                    # noqa: F811
):
    """
    Verify that packets dropped by the standby port MUX drop ACL
    are not counted as RX_DRP.

    Test steps:
        1. Setup: upper ToR is active, lower ToR is standby
           (via toggle_all_simulator_ports_to_upper_tor fixture).
        2. Select a random mux port on the standby (lower) ToR.
        3. Record the RX_DRP counter on the standby mux port.
        4. Send packets from PTF (T1 interface) destined to the
           server behind the selected standby mux port.
        5. Wait for counters to update.
        6. Record the RX_DRP counter again.
        7. Assert that RX_DRP was NOT incremented on the standby port.
        8. Verify ToR states remain correct.
    """
    if cable_type == CableType.active_active:
        pytest.skip("Test is only applicable for active-standby cable type")

    standby_tor = lower_tor_host
    active_tor = upper_tor_host

    # Select a random mux port on the standby ToR
    server_ips = mux_cable_server_ip(standby_tor)
    test_interface = random.choice(list(server_ips.keys()))
    target_server_ip = server_ips[test_interface]['server_ipv4'].split('/')[0]
    logger.info("Selected test interface: %s, target server IP: %s",
                test_interface, target_server_ip)

    # Get the PTF T1 interface to send traffic from
    ptf_t1_intfs = get_t1_ptf_ports(standby_tor, tbinfo)
    ptf_t1_intf = random.choice(ptf_t1_intfs)
    ptf_t1_port = int(ptf_t1_intf.strip("eth"))
    logger.info("Sending traffic from PTF T1 interface: %s (port index: %d)",
                ptf_t1_intf, ptf_t1_port)

    # Build the packet destined to the server behind the standby mux port
    pkt, _ = build_packet_to_server(standby_tor, ptfadapter, target_server_ip)

    # Record RX_DRP counter before sending traffic
    rx_drp_before = get_rx_drp_count(standby_tor, test_interface)
    logger.info("RX_DRP counter before test on %s: %d",
                test_interface, rx_drp_before)

    # Send packets from PTF to the standby mux port
    logger.info("Sending %d packets from PTF T1 port %d to server %s",
                PACKETS_TO_SEND, ptf_t1_port, target_server_ip)
    testutils.send(ptfadapter, ptf_t1_port, pkt, count=PACKETS_TO_SEND)

    # Wait for counters to update
    time.sleep(COUNTER_POLL_WAIT)

    # Record RX_DRP counter after sending traffic
    rx_drp_after = get_rx_drp_count(standby_tor, test_interface)
    logger.info("RX_DRP counter after test on %s: %d",
                test_interface, rx_drp_after)

    # Verify RX_DRP was not incremented
    rx_drp_increase = rx_drp_after - rx_drp_before
    logger.info("RX_DRP increase on %s: %d", test_interface, rx_drp_increase)

    assert rx_drp_increase == 0, (
        "RX_DRP counter was incremented by {} on standby interface {} "
        "after sending {} packets. Packets dropped by MUX drop ACL "
        "should not be counted as RX_DRP.".format(
            rx_drp_increase, test_interface, PACKETS_TO_SEND
        )
    )

    # Verify the ToR states remain correct
    verify_tor_states(
        expected_active_host=active_tor,
        expected_standby_host=standby_tor
    )
