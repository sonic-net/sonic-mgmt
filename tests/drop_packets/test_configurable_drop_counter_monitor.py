"""
Tests the configurable drop counter monitor functionality.

See the HLD for the feature under test:
https://github.com/sonic-net/SONiC/pull/1912
"""

import logging
import random
import time

import pytest

from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # noqa: F401

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
    add_default_route_to_dut,
    ignore_expected_loganalyzer_exception,
    send_packets,
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

_CONFIG_DB_MONITOR_KEY = "'DEBUG_DROP_MONITOR|CONFIG'"
_CONFIG_DB_MONITOR_EXISTS = "sonic-db-cli CONFIG_DB EXISTS " + _CONFIG_DB_MONITOR_KEY
_CONFIG_DB_MONITOR_DEL = "sonic-db-cli CONFIG_DB DEL " + _CONFIG_DB_MONITOR_KEY

# The drop counts are polled at a predefined 60-second interval
# So to register as seperate incidents the drops must be set apart
# by atleast 60 seconds.
# Taking a 5 second buffer to avoid any timing related flakiness
POLL_INTERVAL = 65


@pytest.fixture(scope="module", autouse=True)
def skip_if_drop_monitor_unsupported(duthosts, rand_one_dut_hostname):
    """
    Skip every test in this module when the DUT does not support the drop monitor.

    Autouse and module scoped, so it costs one probe per module and needs no wiring
    in the individual tests.
    """
    duthost = duthosts[rand_one_dut_hostname]
    supported, reason = cdc.is_drop_monitor_supported(duthost)
    if not supported:
        pytest.skip("Drop counter monitor is not supported on {}: {}"
                    .format(duthost.hostname, reason))


@pytest.fixture(autouse=True)
def ignore_drop_monitor_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    """
    Installing and removing debug counters makes some platforms emit SAI errors that have
    nothing to do with the monitor logic under test. These belong to the same
    SAI_OBJECT_TYPE_NULL / brcm_sai families that test_configurable_drop_counters.py already
    ignores.
    """
    if not loganalyzer:
        return

    ignore_regex_list = [
        ".*ERR syncd[0-9]*#syncd.*bulkAddCounter: Object type and field combination is not "
        "supported.*SAI_OBJECT_TYPE_NULL.*",
        ".*ERR syncd[0-9]*#syncd.*runRedisScript: Got EMPTY response type from redis.*",
        ".*ERR syncd[0-9]*#syncd.*SAI_API_DEBUG_COUNTER:"
        "_brcm_sai_get_acl_any_drop_reason_counter.*getting dbg ctr failed.*",
        ".*ERR swss[0-9]*#orchagent.*doTask: Unknown operation type DEL.*",
    ]

    duthost = duthosts[rand_one_dut_hostname]
    loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_list)


@pytest.fixture(autouse=True)
def restore_drop_monitor_config(duthosts, rand_one_dut_hostname):
    """
    Enabling or disabling the drop monitor creates the DEBUG_DROP_MONITOR|CONFIG entry in
    CONFIG_DB. Remove it afterwards if it was not present beforehand, so that the framework's
    post-test config_db_check does not report a leaked config entry.
    """
    duthost = duthosts[rand_one_dut_hostname]
    existed = duthost.command(_CONFIG_DB_MONITOR_EXISTS,
                              module_ignore_errors=True)["stdout"].strip() == "1"

    yield

    if not existed:
        duthost.command(_CONFIG_DB_MONITOR_DEL, module_ignore_errors=True)


@pytest.fixture
def drop_counter(duthosts, rand_one_dut_hostname, device_capabilities):   # noqa: F811
    """
    Creates a drop counter to attach the monitor to, and cleans it up afterwards.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Not every platform supports this counter type / drop reason. Skip rather than fail, the
    # same way the `setup_counters` fixture in test_configurable_drop_counters.py does.
    if PORT_INGRESS_COUNTER_TYPE not in device_capabilities["counters"]:
        pytest.skip("Counter type {} not supported on target DUT"
                    .format(PORT_INGRESS_COUNTER_TYPE))

    supported_reasons = device_capabilities["reasons"][PORT_INGRESS_COUNTER_TYPE]
    unsupported = [r for r in TEST_DROP_REASONS if r not in supported_reasons]
    if unsupported:
        pytest.skip("Drop reasons {} not supported on target DUT".format(unsupported))

    create_drop_counter(duthost, TEST_COUNTER_NAME, PORT_INGRESS_COUNTER_TYPE, TEST_DROP_REASONS)

    yield TEST_COUNTER_NAME

    # The monitor has to be detached while the counter still exists: once the counter is
    # deleted, `config dropcounters disable-monitor -c` fails with "Counter not found".
    try:
        disable_counter_monitor(duthost, TEST_COUNTER_NAME)
    except RunAnsibleModuleFail:
        logging.info("Monitor for counter %s was already disabled", TEST_COUNTER_NAME)
    disable_global_monitor(duthost)
    delete_drop_counter(duthost, TEST_COUNTER_NAME)


def select_monitored_port(duthost, tb_params, counter_name):
    """
    Pick a PTF port index whose DUT-side port is actually polled by the drop monitor.

    Not every port of the DUT is necessarily covered by the monitor plugin, and a port
    that is not polled never raises an incident however much traffic is dropped on it.
    Selecting blindly from the testbed ports therefore yields sporadic failures that
    look like missed incidents.

    Must be called only after both the global and the per-counter monitor are enabled,
    since the plugin publishes its per-port state only while it is running, and the
    first poll can take a full polling interval to land.
    """
    port_map = tb_params["physical_port_map"]
    selected = {}

    def _find_monitored_port():
        monitored = cdc.get_monitored_ports(duthost, counter_name)
        candidates = [ptf_index for ptf_index, dut_port in port_map.items()
                      if dut_port in monitored]
        if not candidates:
            return False
        selected["rx_port"] = random.choice(sorted(candidates))
        return True

    pytest_assert(
        wait_until(2 * POLL_INTERVAL, 5, 0, _find_monitored_port),
        "The drop monitor is not polling any of the testbed ports for counter {}".format(counter_name)
    )

    rx_port = selected["rx_port"]
    logging.info("Selected monitored port %s (%s) to send traffic", rx_port, port_map[rx_port])
    return rx_port


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


def test_monitor_window(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,  # noqa: F811
                        toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                        setup_standby_ports_on_rand_unselected_tor,
                        generate_dropped_packet, add_default_route_to_dut, ptfadapter):  # noqa: F811
    """
    Verifies that incidents older than the configured window are purged and no
    longer count towards the incident_count_threshold.
    """
    duthost = duthosts[rand_one_dut_hostname]
    drop_reason = "DIP_LINK_LOCAL"
    setup_counters([drop_reason])
    # keeping window size 300 to capture drops in the same window
    window = 300
    drop_count_threshold = 5

    src_ip = "10.10.10.10"

    try:
        enable_global_monitor(duthost)
        # incident_count_threshold is irrelevant here since we're only checking
        # that the incident itself is purged from tracking after the window elapses.
        enable_counter_monitor(duthost, DROP_COUNTER_NAME, window, drop_count_threshold, 1)
        pytest_assert(get_counter_config_field(duthost, DROP_COUNTER_NAME,
                                               DROP_MONITOR_STATUS_FIELD) == "enabled",
                      "Per-counter monitor was not enabled")

        rx_port = select_monitored_port(duthost, testbed_params, DROP_COUNTER_NAME)
        dst_port = testbed_params["physical_port_map"][rx_port]
        pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

        # Generate a single incident (drop count exceeds drop_count_threshold).
        send_packets(duthost, ptfadapter, pkt, rx_port, count=drop_count_threshold + 1)
        pytest_assert(
            wait_until(POLL_INTERVAL + window, 2, 0,
                       lambda: cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) >= 1),
            "Incident was not recorded"
        )

        # Let the window fully elapse without generating any more incidents.
        # The purge itself is only applied on the next poll (fixed ~60s cadence,
        # independent of `window`), so we must wait at least POLL_INTERVAL more,
        # for the purge to be reflected.
        pytest_assert(
            wait_until(POLL_INTERVAL + window, 2, 0,
                       lambda: cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) == 0),
            "Outdated incident was not purged after the monitor window elapsed"
        )
    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_drop_count_threshold(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,  # noqa: F811
                              toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
                              setup_standby_ports_on_rand_unselected_tor,         # noqa: F811
                              ptfadapter, drop_reason, generate_dropped_packet,  # noqa: F811
                              add_default_route_to_dut):                                  # noqa: F811
    """
    Tests that a single below-threshold drop count burst never gets registered
    as an incident, and therefore never produces a persistent drop record.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup_counters([drop_reason])

    src_ip = "10.10.10.10"

    try:
        enable_global_monitor(duthost)
        pytest_assert(get_global_monitor_status(duthost) == "enabled",
                      "Global drop monitor was not enabled")

        enable_counter_monitor(duthost, DROP_COUNTER_NAME, MONITOR_WINDOW, DROP_COUNT_THRESHOLD, 1)
        pytest_assert(get_counter_config_field(duthost, DROP_COUNTER_NAME,
                                               DROP_MONITOR_STATUS_FIELD) == "enabled",
                      "Per-counter monitor was not enabled")

        rx_port = select_monitored_port(duthost, testbed_params, DROP_COUNTER_NAME)
        pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)

        rand_count = random.randint(1, DROP_COUNT_THRESHOLD - 1)
        send_packets(duthost, ptfadapter, pkt, rx_port, count=rand_count)

        # Give the monitor time to poll and (incorrectly) register an incident, if it were to.
        def _no_new_record():
            new_count = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before
            return new_count == 0

        pytest_assert(
            wait_until(POLL_INTERVAL + 10, 5, 0, _no_new_record),
            "Drop entry was created prematurely for a below-threshold drop count"
        )
    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_incident_detection_threshold(testbed_params, setup_counters, duthosts,  # noqa: F811
                                      rand_one_dut_hostname,
                                      toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
                                      setup_standby_ports_on_rand_unselected_tor,         # noqa: F811
                                      drop_reason, generate_dropped_packet,  # noqa: F811
                                      add_default_route_to_dut, ptfadapter):                       # noqa: F811
    """
    Tests that persistent drops are only reported once the number of incidents
    within the configured window exceeds incident_count_threshold.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup_counters([drop_reason])
    # keeping window size 700 to capture drops in the same window
    window = 700
    drop_count_threshold = 5

    src_ip = "10.10.10.10"

    try:
        enable_global_monitor(duthost)
        pytest_assert(get_global_monitor_status(duthost) == "enabled",
                      "Global drop monitor was not enabled")

        enable_counter_monitor(duthost, DROP_COUNTER_NAME, window,
                               drop_count_threshold, INCIDENT_COUNT_THRESHOLD)
        pytest_assert(get_counter_config_field(duthost, DROP_COUNTER_NAME,
                                               DROP_MONITOR_STATUS_FIELD) == "enabled",
                      "Per-counter monitor was not enabled")

        rx_port = select_monitored_port(duthost, testbed_params, DROP_COUNTER_NAME)
        pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)
        for i in range(INCIDENT_COUNT_THRESHOLD + 1):
            send_packets(duthost, ptfadapter, pkt, rx_port, count=drop_count_threshold + 1)
            if i < INCIDENT_COUNT_THRESHOLD:
                # Not enough incidents yet: no persistent drop record should exist.
                pytest_assert(
                    (_persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before) == 0,
                    "Drop entry was created prematurely"
                )
                # Wait for the next poll cycle so the next burst registers as a new incident.
                time.sleep(POLL_INTERVAL)

        # verify that the drop entry is created after exceeding the threshold
        def _one_new_record():
            new_count = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before
            return new_count == 1

        pytest_assert(
            wait_until(POLL_INTERVAL + 10, 5, 0, _one_new_record),
            "Drop entry was not created after exceeding the threshold"
        )

    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")
