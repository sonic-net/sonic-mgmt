import ipaddress
import logging
import os.path
import pytest
import random
import time
import scapy.all as scapyall

from ptf import testutils

from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                      # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                      # noqa: F401
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import force_active_tor                                    # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor      # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                         # noqa: F401
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor                        # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                                  # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                                # noqa: F401
from tests.common.helpers import bgp
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import is_ipv4_address
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.parametrize("test_device_interface", ["Loopback1", "Loopback3"], indirect=True)
def test_bgp_block_loopback1(
    bgp_neighbors, upper_tor_host, lower_tor_host,          # noqa: F811
    ptfadapter, ptfhost, setup_interfaces, 
    toggle_all_simulator_ports_to_upper_tor, tbinfo,        # noqa: F811
    tunnel_traffic_monitor, vmhost                          # noqa: F811
):
    """
    Test BGP block on Loopback1 interface and allowed on Loopback3 interface.
    """
    def verify_bgp_session(duthost, bgp_neighbor, should_be_established=True):
        """Verify the bgp session to the DUT is established."""
        bgp_facts = duthost.bgp_facts()["ansible_facts"]
        assert bgp_neighbor.ip in bgp_facts["bgp_neighbors"]
        state = bgp_facts["bgp_neighbors"][bgp_neighbor.ip]["state"]
        if should_be_established:
            assert state == "established", f"BGP session to {bgp_neighbor.ip} is not established, state: {state}"
        else:
            assert state != "established", f"BGP session to {bgp_neighbor.ip} should not be established, state: {state}"

    upper_tor_bgp_neighbor = bgp_neighbors["upper_tor"]
    lower_tor_bgp_neighbor = bgp_neighbors["lower_tor"]

    try:
        # STEP 1: create peer sessions with both ToRs
        lower_tor_bgp_neighbor.start_session()
        upper_tor_bgp_neighbor.start_session()

        time.sleep(10)  # wait for BGP sessions to establish

        # STEP 2: verify BGP sessions are established
        if setup_interfaces["upper_tor"]["local_intf"] == "Loopback1":
            verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor, should_be_established=False)
            verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor, should_be_established=False)
        else:
            verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor, should_be_established=True)
            verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor, should_be_established=True)
    finally:
        upper_tor_bgp_neighbor.stop_session()
        lower_tor_bgp_neighbor.stop_session()
