import pytest
import time

from tests.common.dualtor.dual_tor_utils import upper_tor_host                                      # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                      # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor      # noqa: F401

pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.enable_active_active
@pytest.mark.parametrize("test_device_interface", ["Loopback3", "Loopback1"], indirect=True)
def test_bgp_block_loopback1(
    bgp_neighbors, upper_tor_host, lower_tor_host,                  # noqa: F811
    setup_interfaces, toggle_all_simulator_ports_to_upper_tor,      # noqa: F811
    test_device_interface
):
    """
    Test BGP block on Loopback1 interface and allowed on Loopback3 interface.
    """
    def verify_bgp_session(duthost, bgp_neighbor, should_be_established=True):
        """Verify the bgp session to the DUT is established."""
        bgp_facts = duthost.bgp_facts()["ansible_facts"]
        if should_be_established:
            assert bgp_neighbor.ip in bgp_facts["bgp_neighbors"]
            state = bgp_facts["bgp_neighbors"][bgp_neighbor.ip]["state"]
            assert state == "established", f"BGP session to {bgp_neighbor.ip} is not established, state: {state}"
        else:
            assert bgp_neighbor.ip not in bgp_facts["bgp_neighbors"]

    upper_tor_bgp_neighbor = bgp_neighbors["upper_tor"]
    lower_tor_bgp_neighbor = bgp_neighbors["lower_tor"]

    try:
        # STEP 1: create peer sessions with both ToRs
        lower_tor_bgp_neighbor.start_session()
        upper_tor_bgp_neighbor.start_session()

        time.sleep(30)  # wait for BGP sessions to establish

        # STEP 2: verify BGP sessions are dropped on loopback1 and established on Loopback3
        if test_device_interface == "Loopback1":
            verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor, should_be_established=False)
            verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor, should_be_established=False)
        else:
            verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor, should_be_established=True)
            verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor, should_be_established=True)

    finally:
        upper_tor_bgp_neighbor.stop_session()
        lower_tor_bgp_neighbor.stop_session()
