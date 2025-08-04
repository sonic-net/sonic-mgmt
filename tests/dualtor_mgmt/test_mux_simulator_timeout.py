import pytest
import time
import requests
import logging
import threading
import os
import random
from typing import List
from tests.common.helpers.assertions import pytest_assert

pytestmark = [pytest.mark.topology("dualtor")]

# Environment-configurable parameters
FLOOD_COUNT = int(os.environ.get("FLOOD_COUNT", 4000))
OVERFLOW_THRESHOLD = int(os.environ.get("OVERFLOW_THRESHOLD", 5))
QUEUE_CONSUME_WAIT = int(os.environ.get("QUEUE_CONSUME_WAIT", 10))


@pytest.fixture(scope="function")
def cleanup_mux_simulator(restart_mux_simulator):
    """Restart mux simulator after test completes."""
    yield
    logging.warning("Restarting mux simulator in teardown...")
    restart_mux_simulator()
    time.sleep(2)


def log_listen_queue_metrics(stage: str, localhost):
    """Log listen queue metrics using ss -lt."""
    try:
        output = localhost.shell("ss -lt")["stdout"]
        logging.warning(f"[{stage}] Listen queue metrics from 'ss -lt':\n{output}")
    except Exception as e:
        logging.warning(f"Failed to get listen queue metrics: {e}")


def check_accept_queue_overflow(localhost, threshold=OVERFLOW_THRESHOLD):
    """Check if any socket's Recv-Q exceeds the overflow threshold."""
    try:
        output = localhost.shell("ss -lt")["stdout"]
        logging.warning(f"Checking accept queue overflow with 'ss -lt':\n{output}")
        lines = output.splitlines()
        max_recv_q = 0
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper() == "LISTEN":
                recv_q = int(parts[1])
                max_recv_q = max(max_recv_q, recv_q)
                if recv_q > threshold:
                    logging.warning(f"Accept queue overflow detected: {line.strip()} | Recv-Q = {recv_q}")
                    return True
        logging.warning(f"No accept queue overflow. Max Recv-Q = {max_recv_q}")
        return False
    except Exception as e:
        logging.warning(f"Error in check_accept_queue_overflow: {e}")
        return False


def flood_toggle_all_random_side(url):
    """Flood mux simulator with toggle requests to random sides."""
    toggle_url = url(action="toggle_all")
    sides = ["upper_tor", "lower_tor", "nic"]
    logging.warning(f"Flooding mux server at {toggle_url} with {FLOOD_COUNT} requests")
    for i in range(FLOOD_COUNT):
        try:
            random_side = random.choice(sides)
            payload = {"active_side": random_side}
            requests.post(toggle_url, json=payload, timeout=0.05)
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException as e:
            logging.warning(f"Flood {i} - Toggle random side request exception: {e}")


def send_drop_request_random_side(url):
    """Send a drop request to a random side."""
    try:
        drop_url = url(action="drop")
        random_side = random.choice(["upper_tor", "nic"])
        response = requests.post(drop_url, json={"out_sides": [random_side]}, timeout=0.05)
        return response
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException as e:
        logging.warning(f"Drop request exception: {e}")
        return None


def wait_until_queue_consumed(timeout=QUEUE_CONSUME_WAIT):
    """Wait for accept queue to be consumed."""
    logging.warning("Waiting for accept queue to be consumed...")
    time.sleep(timeout)


def retry_get_mux_status(get_mux_status, iface: str, retries=3, delay=1):
    """Retry mux status retrieval with delay."""
    for _ in range(retries):
        status = get_mux_status(interface_name=iface)
        if status and "active_side" in status and not status.get("stale_request", False):
            return status
        time.sleep(delay)
    return None


def test_mux_simulator_toggle_all_accept_queue_overflow(
    active_standby_ports: List[str],
    url,
    get_mux_status,
    localhost,
    cleanup_mux_simulator
):
    """Test mux simulator accept queue overflow behavior."""

    log_listen_queue_metrics("Before toggle all random flood", localhost)

    toggle_thread = threading.Thread(target=flood_toggle_all_random_side, args=(url,))
    toggle_thread.start()
    time.sleep(1)  # Allow queue to potentially overflow

    overflow = False
    # Retry accept queue overflow check several times with delay
    for _ in range(5):
        if check_accept_queue_overflow(localhost):
            overflow = True
            break
        time.sleep(1)

    pytest_assert(overflow, "Accept queue overflow expected")

    # During overflow, new drop requests should not be accepted
    new_response = send_drop_request_random_side(url)
    pytest_assert(new_response is None or new_response.status_code != 200,
                  "New request unexpectedly accepted during overflow")

    toggle_thread.join()
    wait_until_queue_consumed()

    # After queue consumption, drop requests should again be accepted
    post_response = send_drop_request_random_side(url)
    pytest_assert(post_response is not None and post_response.status_code == 200,
                  "New drop request not accepted after queue consumption")

    log_listen_queue_metrics("After toggle & drop flood queue consumption", localhost)

    test_ports = active_standby_ports[:3] if len(active_standby_ports) >= 3 else active_standby_ports
    for iface in test_ports:
        status = retry_get_mux_status(get_mux_status, iface)
        pytest_assert(status is not None, f"Could not retrieve mux status for interface {iface}")
        pytest_assert("active_side" in status, f"Expected 'active_side' key missing in mux status for {iface}")
        pytest_assert(not status.get("stale_request", False), f"Stale request detected for {iface}")

    # Verify simulator accepts normal toggle all request after timeouts and cleanup
    toggle_url = url(action="toggle_all")
    response = requests.post(toggle_url, json={"active_side": "random"}, timeout=3)
    pytest_assert(response.status_code == 200,
                  "Simulator did not accept normal toggle all request after timeouts and cleanup")
