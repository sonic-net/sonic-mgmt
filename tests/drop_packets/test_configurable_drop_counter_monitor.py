"""
Tests the configurable drop counter monitor functionality.

See the HLD for the feature under test:
https://github.com/sonic-net/SONiC/pull/1912
"""

import logging
import random
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

from . import configurable_drop_counters as cdc
from .configurable_drop_counters import (
    PORT_INGRESS_COUNTER_TYPE,
    enable_counter_monitor,
    disable_counter_monitor,
    enable_global_monitor,
    disable_global_monitor,
    show_persistent_drops,
    get_global_monitor_status,
    get_counter_config_field,
    create_drop_counter,
    delete_drop_counter,
)
from .test_configurable_drop_counters import (   # noqa: F401
    vlan_mac,
    testbed_params,
    device_capabilities,
    setup_counters,
    generate_dropped_packet,
    send_dropped_traffic,
    add_default_route_to_dut,
)


pytestmark = [
    pytest.mark.topology('any')
]

TEST_COUNTER_NAME = "MONITOR_TEST_COUNTER"
TEST_DROP_REASONS = ["L3_ANY"]

# The "TEST" counter is the fixed name used by the `setup_counters` fixture
DROP_COUNTER_NAME = "TEST"

MONITOR_WINDOW = 60
DROP_COUNT_THRESHOLD = 20
INCIDENT_COUNT_THRESHOLD = 5

DROP_MONITOR_STATUS_FIELD = "drop_monitor_status"
PERSISTENT_DROP_MESSAGE = "Persistent packet drops detected"

LINK_LOCAL_IP = "169.254.0.1"

# The drop counts are polled at a predefined 60-second interval
# So to register as seperate incidents the drops must be set apart
# by atleast 60 seconds.
# Taking a 5 second buffer to avoid any timing related flakiness
POLL_INTERVAL = 65


@pytest.fixture
def drop_counter(duthosts, rand_one_dut_hostname):
    """
    Creates a drop counter to attach the monitor to, and cleans it up afterwards.
    """
    duthost = duthosts[rand_one_dut_hostname]

    create_drop_counter(duthost, TEST_COUNTER_NAME, PORT_INGRESS_COUNTER_TYPE, TEST_DROP_REASONS)

    yield TEST_COUNTER_NAME

    delete_drop_counter(duthost, TEST_COUNTER_NAME)
    disable_counter_monitor(duthost, TEST_COUNTER_NAME)
    disable_global_monitor(duthost)


def _persistent_drop_records_count(duthost, counter_name):
    """Return the set of persistent-drop record lines currently reported for a counter."""
    count = 0
    result = show_persistent_drops(duthost, counter_name)
    # Get the lines, defaulting to an empty list if not found
    lines = result.get("stdout_lines", [])

    for line in lines:
        if PERSISTENT_DROP_MESSAGE in line:
            count += 1

    return count


def test_global_monitor_enable_disable(duthosts, rand_one_dut_hostname):
    """
    Tests enabling and disabling the global drop counter monitor.
    """
    duthost = duthosts[rand_one_dut_hostname]

    try:
        enable_global_monitor(duthost)
        pytest_assert(get_global_monitor_status(duthost) == "enabled",
                      "Global drop monitor was not enabled")
    finally:
        disable_global_monitor(duthost)
        pytest_assert(get_global_monitor_status(duthost) == "disabled",
                      "Global drop monitor was not disabled")


def test_counter_monitor_enable_disable(duthosts, rand_one_dut_hostname, drop_counter):
    """
    Tests enabling and disabling the per-counter drop monitor.

    Also verifies that when the global monitor is disabled, the CLI refuses to
    enable the per-counter monitor, issues a warning, and leaves the per-counter
    monitor status unchanged.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Global monitor disabled: enabling the per-counter monitor must be rejected with a warning.
    disable_global_monitor(duthost)
    pytest_assert(get_global_monitor_status(duthost) == "disabled",
                  "Global drop monitor was not disabled")

    result = enable_counter_monitor(duthost, drop_counter, MONITOR_WINDOW,
                                    DROP_COUNT_THRESHOLD, INCIDENT_COUNT_THRESHOLD)
    pytest_assert("Global Persistent Drop Counter Monitor is currently disabled" in result["stdout"],
                  "Expected a warning when enabling counter monitor while global monitor is disabled, "
                  "got: {}".format(result["stdout"]))
    pytest_assert(get_counter_config_field(duthost, drop_counter, DROP_MONITOR_STATUS_FIELD)
                  in ("", "disabled"),
                  "Per-counter monitor status changed while global monitor was disabled")

    # Global monitor enabled: the per-counter monitor can now be enabled.
    enable_global_monitor(duthost)
    pytest_assert(get_global_monitor_status(duthost) == "enabled",
                  "Global drop monitor was not enabled")

    enable_counter_monitor(duthost, drop_counter, MONITOR_WINDOW,
                           DROP_COUNT_THRESHOLD, INCIDENT_COUNT_THRESHOLD)
    pytest_assert(get_counter_config_field(duthost, drop_counter,
                                           DROP_MONITOR_STATUS_FIELD) == "enabled",
                  "Per-counter monitor was not enabled")

    disable_counter_monitor(duthost, drop_counter)
    pytest_assert(get_counter_config_field(duthost, drop_counter,
                                           DROP_MONITOR_STATUS_FIELD) == "disabled",
                  "Per-counter monitor was not disabled")

def test_monitor_window(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,
                        send_dropped_traffic, generate_dropped_packet,       # noqa: F811
                        add_default_route_to_dut):                          # noqa: F811
    """
    Verifies that incidents older than the configured window are purged and no
    longer count towards the incident_count_threshold.
    """
    duthost = duthosts[rand_one_dut_hostname]
    drop_reason = "DIP_LINK_LOCAL"
    counter_type = setup_counters([drop_reason])

    window = 15
    drop_count_threshold = 5

    rx_port = random.choice(list(testbed_params["physical_port_map"].keys()))
    dst_port = testbed_params["physical_port_map"][rx_port]
    logging.info("Selected port %s to send traffic", rx_port)

    src_ip = "10.10.10.10"
    pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

    try:
        enable_global_monitor(duthost)
        # incident_count_threshold is irrelevant here since we're only checking
        # that the incident itself is purged from tracking after the window elapses.
        enable_counter_monitor(duthost, DROP_COUNTER_NAME, window, drop_count_threshold, 100)
        pytest_assert(get_counter_config_field(duthost, DROP_COUNTER_NAME,
                                               DROP_MONITOR_STATUS_FIELD) == "enabled",
                      "Per-counter monitor was not enabled")

        # Generate a single incident (drop count exceeds drop_count_threshold).
        send_dropped_traffic(counter_type, pkt, rx_port, count=drop_count_threshold + 1)
        pytest_assert(
            wait_until(window, 2, 0,
                       lambda: cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) >= 1),
            "Incident was not recorded"
        )

        # Let the window fully elapse without generating any more incidents.
        # The purge itself is only applied on the next poll (fixed ~60s cadence,
        # independent of `window`), so we must wait at least POLL_INTERVAL more,
        # for the purge to be reflected.
        time.sleep(window)
        pytest_assert(
            wait_until(POLL_INTERVAL, 2, 0,
                       lambda: cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) == 0),
            "Outdated incident was not purged after the monitor window elapsed"
        )
    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_drop_count_threshold(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,
                              send_dropped_traffic, drop_reason, generate_dropped_packet,  # noqa: F811
                              add_default_route_to_dut):                                  # noqa: F811
    """
    Tests that a single below-threshold drop count burst never gets registered
    as an incident, and therefore never produces a persistent drop record.
    """
    duthost = duthosts[rand_one_dut_hostname]
    counter_type = setup_counters([drop_reason])

    rx_port = random.choice(list(testbed_params["physical_port_map"].keys()))
    logging.info("Selected port %s to send traffic", rx_port)

    src_ip = "10.10.10.10"
    pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

    try:
        enable_global_monitor(duthost)
        pytest_assert(get_global_monitor_status(duthost) == "enabled",
                      "Global drop monitor was not enabled")

        enable_counter_monitor(duthost, DROP_COUNTER_NAME, MONITOR_WINDOW, DROP_COUNT_THRESHOLD, 1)
        pytest_assert(get_counter_config_field(duthost, DROP_COUNTER_NAME,
                                               DROP_MONITOR_STATUS_FIELD) == "enabled",
                      "Per-counter monitor was not enabled")

        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)

        rand_count = random.randint(1, DROP_COUNT_THRESHOLD - 1)
        send_dropped_traffic(counter_type, pkt, rx_port, count=rand_count)

        # Give the monitor time to poll and (incorrectly) register an incident, if it were to.
        time.sleep(POLL_INTERVAL)
        pytest_assert(
            (_persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before) == 0,
            "Drop entry was created prematurely for a below-threshold drop count"
        )
    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_incident_detection_threshold(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,
                                      send_dropped_traffic, drop_reason, generate_dropped_packet,  # noqa: F811
                                      add_default_route_to_dut):                                   # noqa: F811
    """
    Tests that persistent drops are only reported once the number of incidents
    within the configured window exceeds incident_count_threshold.
    """
    duthost = duthosts[rand_one_dut_hostname]
    counter_type = setup_counters([drop_reason])

    window = 600
    drop_count_threshold = 5

    rx_port = random.choice(list(testbed_params["physical_port_map"].keys()))
    logging.info("Selected port %s to send traffic", rx_port)

    src_ip = "10.10.10.10"
    pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

    try:
        enable_global_monitor(duthost)
        pytest_assert(get_global_monitor_status(duthost) == "enabled",
                      "Global drop monitor was not enabled")

        enable_counter_monitor(duthost, DROP_COUNTER_NAME, window,
                               drop_count_threshold, INCIDENT_COUNT_THRESHOLD)
        pytest_assert(get_counter_config_field(duthost, DROP_COUNTER_NAME,
                                               DROP_MONITOR_STATUS_FIELD) == "enabled",
                      "Per-counter monitor was not enabled")

        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)

        for i in range(INCIDENT_COUNT_THRESHOLD + 1):
            send_dropped_traffic(counter_type, pkt, rx_port, count=drop_count_threshold + 1)

            if i < INCIDENT_COUNT_THRESHOLD:
                # Not enough incidents yet: no persistent drop record should exist.
                pytest_assert(
                    (_persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before) == 0,
                    "Drop entry was created prematurely"
                )
                # Wait for the next poll cycle so the next burst registers as a new incident.
                time.sleep(POLL_INTERVAL)

        # verify that the drop entry is created after exceeding the threshold
        pytest_assert(
            wait_until(POLL_INTERVAL + 10, 5, 0,
                       lambda: bool(_persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before) == 1),
            "Drop entry was not created after exceeding the threshold"
        )

        # Generate some more incidents and verify the incident count
        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)
        rand_incident_count = random.randint(1, 10)
        for i in range(rand_incident_count):
            for j in range(INCIDENT_COUNT_THRESHOLD + 1):
                send_dropped_traffic(counter_type, pkt, rx_port, count=drop_count_threshold + 1)
                time.sleep(POLL_INTERVAL)
        # Verify the incident count
        pytest_assert(
            (_persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before) == rand_incident_count,
            "Incident count did not match the expected value"
        )

    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")