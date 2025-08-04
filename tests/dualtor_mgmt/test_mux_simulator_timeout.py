import pytest
import time
import requests
import logging
import threading
from typing import List
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.fixture(scope="function")
def cleanup_mux_simulator(restart_mux_simulator):
    """
    Fixture to restart mux_simulator **after** test completes.
    Ensures environment cleanup regardless of test outcome.
    """
    yield
    logging.info("Restarting mux simulator in teardown...")
    restart_mux_simulator()
    time.sleep(2)


def test_mux_simulator_toggle_all_accept_queue_overflow(
    active_standby_ports: List[str],
    url,
    get_mux_status,
    localhost,
    cleanup_mux_simulator,
):
    """
    Test mux_simulator handling of accept queue overflow using toggle all API timeout flood.
    """

    def log_listen_queue_metrics(stage: str):
        cmd = "netstat -s | grep -i listen"
        output = localhost.shell(cmd)["stdout"]
        logging.info(f"[{stage}] Listen queue metrics:\n{output}")

    def flood_toggle_all_timeouts():
        toggle_all_url = url(action="toggle_all", toggle_action="drop")
        for _ in range(2000):
            try:
                requests.post(
                    toggle_all_url,
                    json={"action": "toggle", "out_sides": ["upper_tor", "lower_tor", "nic"]},
                    timeout=0.1,
                )
            except requests.exceptions.Timeout:
                # Expected timeout, ignore
                pass
            except requests.exceptions.RequestException as e:
                logging.warning(f"Toggle all request exception: {e}")

    def send_timeout_request():
        try:
            toggle_all_url = url(action="toggle_all", toggle_action="drop")
            response = requests.post(
                toggle_all_url,
                json={"action": "toggle", "out_sides": ["upper_tor", "lower_tor", "nic"]},
                timeout=0.1,
            )
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request exception: {e}")
            return None

    def check_accept_queue_overflow():
        cmd = "netstat -s | grep -i 'listen queue overflow'"
        output = localhost.shell(cmd)["stdout"]
        logging.info(f"Accept queue overflow check output:\n{output}")
        return "listen queue overflow" in output.lower()

    def wait_until_queue_consumed(timeout=10):
        logging.info("Waiting for accept queue to be consumed...")
        time.sleep(timeout)

    def retry_get_mux_status(iface: str, retries=3, delay=1):
        for _ in range(retries):
            status = get_mux_status(interface_name=iface)
            if status and "active_side" in status and not status.get("stale_request", False):
                return status
            time.sleep(delay)
        return None

    # Log listen queue metrics before flooding
    log_listen_queue_metrics("Before Toggle All Flood")

    # Start flooding toggle all timeout requests in a separate thread
    toggle_thread = threading.Thread(target=flood_toggle_all_timeouts)
    toggle_thread.start()

    time.sleep(1)  # short delay to let accept queue potentially overflow

    # Step 1: Check accept queue overflow
    pytest_assert(check_accept_queue_overflow(), "Accept queue did not overflow as expected")

    # Step 2: Attempt sending a new request during overflow
    new_response = send_timeout_request()
    pytest_assert(
        new_response is None or (new_response.status_code != 200),
        "New request unexpectedly accepted during overflow"
    )

    toggle_thread.join()

    # Step 3: Wait for accept queue to be consumed
    wait_until_queue_consumed()

    # Step 4: Send new request after consumption, expect acceptance
    post_response = send_timeout_request()
    pytest_assert(
        post_response is not None and post_response.status_code == 200,
        "New request not accepted after queue consumption"
    )

    # Log listen queue metrics after flooding & consumption
    log_listen_queue_metrics("After Toggle All Flood & Queue Consumption")

    # Validate per-port mux status for stale requests
    test_ports = active_standby_ports[:3] if len(active_standby_ports) >= 3 else active_standby_ports
    for iface in test_ports:
        status = retry_get_mux_status(iface)
        pytest_assert(status is not None, f"Could not retrieve mux status for interface {iface}")
        pytest_assert("active_side" in status, f"Expected 'active_side' key missing in mux status for {iface}")
        pytest_assert(not status.get("stale_request", False), f"Stale request detected for {iface}")

    # Final check: mux simulator accepts a new normal toggle all request
    toggle_all_url = url(action="toggle_all")
    response = requests.post(
        toggle_all_url,
        json={"action": "toggle", "out_sides": ["upper_tor"]},
        timeout=3,
    )
    pytest_assert(
        response.status_code == 200,
        "Simulator did not accept normal toggle all request after timeouts and cleanup"
    )
