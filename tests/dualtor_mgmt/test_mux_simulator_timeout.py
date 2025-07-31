import pytest
import time
import requests
import logging
from typing import List

pytestmark = [
    pytest.mark.topology("dualtor")
]


def test_mux_simulator_timeout_cleanup(
    duthosts,
    tbinfo,
    active_standby_ports: List[str],
    url,
    get_mux_status,
    restart_mux_simulator
) -> None:
    """
    Validate that mux_simulator correctly handles and cleans up timeout requests.

    Test steps:
    1. Restart mux_simulator to begin with a clean state.
    2. Flood mux_simulator with multiple requests designed to timeout.
    3. Allow mux_simulator time to clean up timed-out requests.
    4. Assert no stale requests remain in mux_simulator’s state.
    5. Verify mux_simulator accepts new valid requests post-timeout flooding.
    """

    # Restart mux_simulator to ensure a clean start
    restart_mux_simulator()
    time.sleep(2)  # wait for simulator to fully restart

    # Select up to 3 active ports to run timeout tests on
    test_ports = active_standby_ports[:3] if len(active_standby_ports) >= 3 else active_standby_ports

    # Flood mux_simulator with timeout-inducing requests
    for iface in test_ports:
        timeout_request_url = url(interface_name=iface, action="drop")  # 'drop' action triggers timeout simulation
        for _ in range(10):
            try:
                requests.post(
                    timeout_request_url,
                    json={"out_sides": ["upper_tor", "lower_tor", "nic"]},
                    timeout=0.1,  # very short timeout to force client-side timeout
                )
            except requests.exceptions.Timeout:
                # Expected timeout; no action needed
                pass
            except requests.exceptions.RequestException as e:
                # Optional: log unexpected exceptions for debugging
                logging.warning(f"Non-timeout request exception on {iface}: {e}")

    # Allow mux_simulator time to process and clear timed-out requests
    time.sleep(3.5)

    # Check that mux_simulator has cleaned up stale requests
    for iface in test_ports:
        status = get_mux_status(interface_name=iface)
        assert status is not None, f"Could not retrieve mux status for interface {iface}"
        assert "active_side" in status, f"Expected 'active_side' key missing in mux status for {iface}"
        assert not status.get("stale_request", False), f"Stale request detected for {iface}"

    # Verify mux_simulator accepts new valid requests after timeout cleanup
    for iface in test_ports:
        normal_request_url = url(interface_name=iface, action="output")
        response = requests.post(
            normal_request_url,
            json={"out_sides": ["upper_tor"]},
            timeout=3,
        )
        assert response.status_code == 200, f"Failed to accept new request on {iface} after timeouts"
