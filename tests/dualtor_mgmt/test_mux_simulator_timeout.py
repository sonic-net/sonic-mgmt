import pytest
import time
import requests
import logging
import threading
from typing import List
from tests.common.helpers.assertions import pytest_assert
import random

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
    Test mux_simulator handling of accept queue overflow using mux simulator's documented API:
    toggling all muxes to a random side and dropping packets on a random side to cause timeouts.
    """

    def log_listen_queue_metrics(stage: str):
        try:
            output = localhost.shell("ss -lt")["stdout"]
            logging.info(f"[{stage}] Listen queue metrics from 'ss -lt':\n{output}")
        except Exception as e:
            logging.warning(f"Failed to get listen queue metrics: {e}")

    def flood_toggle_all_random_side():
        mux_server_url = url()
        for _ in range(2000):
            try:
                payload = {"active_side": "random"}
                requests.post(mux_server_url, json=payload, timeout=0.1)
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.RequestException as e:
                logging.warning(f"Toggle all random side request exception: {e}")

    def send_drop_request_random_side():
        drop_url = url(action="drop")
        random_side = random.choice(["upper_tor", "lower_tor", "nic"])
        try:
            response = requests.post(
                drop_url,
                json={"out_sides": [random_side]},
                timeout=0.1,
            )
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Drop request exception: {e}")
            return None

    def check_accept_queue_overflow():
        threshold = 5
        try:
            output = localhost.shell("ss -lt")["stdout"]
            logging.info(f"Checking accept queue overflow with 'ss -lt' output:\n{output}")
            lines = output.splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() == "LISTEN":
                    recv_q = int(parts[1])
                    if recv_q > threshold:
                        logging.warning(f"Accept queue overflow detected: {line.strip()}, Recv-Q={recv_q}")
                        return True
            return False
        except Exception as e:
            logging.warning(f"Could not check accept queue overflow: {e}")
            return False

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

    log_listen_queue_metrics("Before toggle all random flood")

    toggle_thread = threading.Thread(target=flood_toggle_all_random_side)
    toggle_thread.start()
    time.sleep(1)  # Allow queue to potentially overflow

    pytest_assert(check_accept_queue_overflow(), "Accept queue did not overflow as expected")

    new_response = send_drop_request_random_side()
    pytest_assert(
        new_response is None or (new_response.status_code != 200),
        "New drop request unexpectedly accepted during overflow"
    )

    toggle_thread.join()

    wait_until_queue_consumed()

    post_response = send_drop_request_random_side()
    pytest_assert(
        post_response is not None and post_response.status_code == 200,
        "New drop request not accepted after queue consumption"
    )

    log_listen_queue_metrics("After toggle all & drop flood and queue consumption")

    test_ports = active_standby_ports[:3] if len(active_standby_ports) >= 3 else active_standby_ports
    for iface in test_ports:
        status = retry_get_mux_status(iface)
        pytest_assert(status is not None, f"Could not retrieve mux status for interface {iface}")
        pytest_assert("active_side" in status, f"'active_side' key missing in mux status for {iface}")
        pytest_assert(not status.get("stale_request", False), f"Stale request detected for {iface}")

    mux_server_url = url()
    response = requests.post(
        mux_server_url,
        json={"active_side": "random"},
        timeout=3,
    )
    pytest_assert(
        response.status_code == 200,
        "Simulator did not accept normal toggle all request after timeouts and cleanup"
    )
