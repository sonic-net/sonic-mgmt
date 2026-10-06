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
_CONFIG_DB_MONITOR_SET_STATUS = ("sonic-db-cli CONFIG_DB HSET " + _CONFIG_DB_MONITOR_KEY
                                 + " status {}")
_CONFIG_DB_COUNTER_KEYS = "sonic-db-cli CONFIG_DB KEYS 'DEBUG_COUNTER|*'"
_CONFIG_DB_COUNTER_SET_MONITOR = ("sonic-db-cli CONFIG_DB HSET 'DEBUG_COUNTER|{}' "
                                  + DROP_MONITOR_STATUS_FIELD + " {}")
_CONFIG_DB_MONITOR_DEL_STATUS = "sonic-db-cli CONFIG_DB HDEL " + _CONFIG_DB_MONITOR_KEY + " status"
_CONFIG_DB_COUNTER_DEL_MONITOR = ("sonic-db-cli CONFIG_DB HDEL 'DEBUG_COUNTER|{}' "
                                  + DROP_MONITOR_STATUS_FIELD)

# The drop counts are polled at a predefined 60-second interval
# So to register as seperate incidents the drops must be set apart
# by atleast 60 seconds.
# Taking a 5 second buffer to avoid any timing related flakiness
POLL_INTERVAL = 65

# Slack allowed on the *purge deadline* only. Expiry is applied on the monitor's fixed
# poll cadence rather than exactly at the window boundary, so the purge may land slightly
# after the window elapses. This is deliberately not used to shorten the retention check:
# the incident must survive the full configured window.
RETENTION_SLACK = 15
# Keeps the final retention sample just inside the window so that an expiry in the
# last seconds before the boundary is still observed rather than stepped over.
RETENTION_SAMPLE_MARGIN = 1


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
        ".*ERR syncd[0-9]*#syncd.*bulkAddCounter: Object type and field combination is not " +
        "supported.*SAI_OBJECT_TYPE_NULL.*",
        ".*ERR syncd[0-9]*#syncd.*runRedisScript: Got EMPTY response type from redis.*",
        ".*ERR syncd[0-9]*#syncd.*SAI_API_DEBUG_COUNTER:" +
        "_brcm_sai_get_acl_any_drop_reason_counter.*getting dbg ctr failed.*",
        ".*ERR swss[0-9]*#orchagent.*doTask: Unknown operation type DEL.*",
    ]

    duthost = duthosts[rand_one_dut_hostname]
    loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_list)


def _counter_monitor_statuses(duthost):
    """
    Map every configured drop counter to its current drop_monitor_status.

    A counter carrying no such field maps to an empty string, and that is a meaningful
    value here: it has to be distinguishable from "disabled" so the field can be removed
    again during cleanup rather than left behind.

    Failures are surfaced rather than skipped. A counter missing from this snapshot would
    be silently excluded from restoration, which is the same destructive outcome the
    snapshot exists to prevent. get_counter_config_field already raises on a failed
    command, so only the key listing needs an explicit check.
    """
    result = duthost.command(_CONFIG_DB_COUNTER_KEYS, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "Could not list the configured drop counters (rc={}): {}".format(
            result["rc"], result.get("stderr", "").strip())
    )
    statuses = {}
    for key in result.get("stdout_lines", []):
        counter_name = key.strip().split("|", 1)[-1]
        if not counter_name:
            continue
        statuses[counter_name] = get_counter_config_field(duthost, counter_name,
                                                          DROP_MONITOR_STATUS_FIELD)
    return statuses


@pytest.fixture(autouse=True)
def restore_drop_monitor_config(duthosts, rand_one_dut_hostname):
    """
    Snapshot the drop monitor configuration and put it back afterwards.

    These tests disable the global monitor during cleanup, and `config dropcounters
    disable-monitor` without a counter name does not only clear the global flag: it walks
    every configured DEBUG_COUNTER and disables that counter's monitor too (see
    DropConfig.disable_drop_monitor in sonic-utilities). Restoring only the global entry
    would therefore still leave every pre-existing counter unmonitored on a shared DUT.

    Only pre-existing state is restored. When the tests created the
    DEBUG_DROP_MONITOR|CONFIG entry it is deleted again, so the framework's post-test
    config_db_check does not report a leaked config entry.
    """
    duthost = duthosts[rand_one_dut_hostname]

    exists_result = duthost.command(_CONFIG_DB_MONITOR_EXISTS, module_ignore_errors=True)
    pytest_assert(
        exists_result["rc"] == 0,
        "Could not determine whether {} already exists (rc={}): {}".format(
            _CONFIG_DB_MONITOR_KEY, exists_result["rc"],
            exists_result.get("stderr", "").strip())
    )
    existed = exists_result["stdout"].strip() == "1"
    # get_global_monitor_status raises on a failed command, so an unreadable status stops
    # the test before it mutates anything rather than being recorded as "absent".
    global_status_before = get_global_monitor_status(duthost) if existed else ""
    monitor_statuses_before = _counter_monitor_statuses(duthost)

    yield

    failures = []

    def _restore(command, description):
        """Run one restore step, recording failures instead of abandoning the rest."""
        try:
            result = duthost.command(command, module_ignore_errors=True)
            if result["rc"] != 0:
                failures.append("{} failed (rc={}): {}".format(
                    description, result["rc"], result.get("stderr", "").strip()))
        except Exception as exc:
            failures.append("{} raised {}".format(description, exc))

    if not existed:
        _restore(_CONFIG_DB_MONITOR_DEL, "deleting the test-created global monitor entry")
    elif global_status_before:
        _restore(_CONFIG_DB_MONITOR_SET_STATUS.format(global_status_before),
                 "restoring the global monitor status")
    else:
        # The entry existed but carried no status field. Enabling or disabling the monitor
        # adds one, so remove it again rather than leaving behind a field that was not
        # there before.
        _restore(_CONFIG_DB_MONITOR_DEL_STATUS,
                 "removing the global status field added by the test")

    for counter_name, status in monitor_statuses_before.items():
        if status:
            _restore(_CONFIG_DB_COUNTER_SET_MONITOR.format(counter_name, status),
                     "restoring {} on counter {}".format(DROP_MONITOR_STATUS_FIELD,
                                                         counter_name))
        else:
            # A global disable writes drop_monitor_status=disabled onto every configured
            # counter, so a counter that had no such field must have it removed again for
            # the restoration to be exact.
            _restore(_CONFIG_DB_COUNTER_DEL_MONITOR.format(counter_name),
                     "removing the {} added on counter {}".format(DROP_MONITOR_STATUS_FIELD,
                                                                  counter_name))

    # Raised from teardown, which pytest reports separately from the test's own outcome,
    # so demanding a complete restoration cannot mask a failure in the test body.
    pytest_assert(
        not failures,
        "Failed to restore the drop monitor configuration: {}".format("; ".join(failures))
    )


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
    """
    Number of persistent-drop record lines currently reported for a counter.

    A failed CLI call is reported as an error rather than counted as zero records. The CLI
    exits non-zero only on a real problem such as a missing counter or a DB error; having
    no records to show is a successful call that simply prints nothing, so the two cases
    are distinguishable and must not be conflated.
    """
    result = show_persistent_drops(duthost, counter_name)
    pytest_assert(
        result["rc"] == 0,
        "'show dropcounters persistent-drops {}' failed (rc={}): {}".format(
            counter_name, result["rc"], result.get("stderr", "").strip())
    )
    return sum(1 for line in result.get("stdout_lines", [])
               if PERSISTENT_DROP_MESSAGE in line)


def _skip_unless_port_counter(counter_type):
    """
    Skip unless the counter under test is one the monitor actually polls.

    The monitor plugin only ever walks COUNTERS_DEBUG_NAME_PORT_STAT_MAP (see
    drop_monitor.lua); switch-level counters are published to the separate
    COUNTERS_DEBUG_NAME_SWITCH_STAT_MAP and are never processed. A DUT advertising
    support for a switch counter therefore says nothing about the per-port monitor state
    these tests need, and without this gate they would fail rather than skip on such a DUT.
    """
    if counter_type != PORT_INGRESS_COUNTER_TYPE:
        pytest.skip("The drop monitor only polls port-level counters, "
                    "{} is never monitored".format(counter_type))


def _wait_for_monitor_poll(duthost, counter_name, dut_port, baseline, expected_delta):
    """
    Block until the monitor completes a poll that has observed the generated traffic.

    The plugin rewrites prev_drop_count for every polled port on every poll, so the stored
    value reaching `baseline + expected_delta` proves a poll ran *after* the drops landed
    on the counter. Assertions about incidents or alerts are only meaningful once that
    boundary has been crossed; evaluated earlier they describe a monitor that has not yet
    looked at the traffic, and would hold for correct and incorrect behaviour alike.

    Note that `sonic-clear dropcounters` only rewrites the CLI's cached baseline files and
    does not reset COUNTERS_DB, so these raw counts stay monotonic across bursts.
    """
    def _poll_completed():
        return cdc.get_monitor_prev_drop_count(duthost, counter_name, dut_port) >= \
            baseline + expected_delta

    pytest_assert(
        wait_until(2 * POLL_INTERVAL, 5, 0, _poll_completed),
        "The drop monitor did not complete a poll of {} after {} drops were generated"
        .format(dut_port, expected_delta)
    )


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


@pytest.mark.dualtor_active_standby_toggle_to_random_tor
@pytest.mark.dualtor_active_active_setup_standby_on_random_unselected_tor
def test_monitor_window(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,  # noqa: F811
                        generate_dropped_packet, add_default_route_to_dut, ptfadapter):  # noqa: F811
    """
    Verifies that incidents older than the configured window are purged and no
    longer count towards the incident_count_threshold.
    """
    duthost = duthosts[rand_one_dut_hostname]
    drop_reason = "DIP_LINK_LOCAL"
    _skip_unless_port_counter(setup_counters([drop_reason]))
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
        burst = drop_count_threshold + 1
        baseline = cdc.get_monitor_prev_drop_count(duthost, DROP_COUNTER_NAME, dst_port)
        send_packets(duthost, ptfadapter, pkt, rx_port, count=burst)
        _wait_for_monitor_poll(duthost, DROP_COUNTER_NAME, dst_port, baseline, burst)

        pytest_assert(cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) >= 1,
                      "Incident was not recorded")

        # Anchor the window on the timestamp the monitor itself recorded. The incident is
        # stamped with the DUT's clock and expiry is evaluated against that value, so it is
        # the only sound reference point.
        incident_ts = cdc.get_first_incident_timestamp(duthost, DROP_COUNTER_NAME, dst_port)
        pytest_assert(incident_ts is not None,
                      "Incident list is empty immediately after an incident was recorded")

        # Lower bound: the incident has to survive the *whole* configured window. The
        # monitor purges only when `now - incident_ts > window`, so the incident must
        # still be present for every sample taken at or before `incident_ts + window`;
        # stopping short of that boundary would let an early expiry slip through the
        # remaining seconds unchecked.
        #
        # The count is deliberately sampled before the clock. The clock reading is then
        # no earlier than the count reading, so an age within the window proves the count
        # was also taken within it. Sampling in the opposite order would leave a gap in
        # which a legitimate purge could be misreported as premature.
        while True:
            incident_count = cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port)
            age = cdc.get_dut_unix_timestamp(duthost) - incident_ts
            if age > window:
                break
            pytest_assert(
                incident_count >= 1,
                "Incident was purged {}s after it was recorded, before the configured "
                "{}s window elapsed".format(age, window)
            )
            # Shrink the interval as the boundary approaches so the last sample lands
            # just inside the window; a fixed interval could step straight over an
            # expiry occurring in the final seconds and never observe it.
            time.sleep(max(0, min(10, window - age - RETENTION_SAMPLE_MARGIN)))

        # Upper bound: once the window has elapsed the incident must be purged. The purge
        # is applied on the fixed poll cadence rather than exactly at expiry, so allow a
        # couple of polls of slack.
        pytest_assert(
            wait_until(2 * POLL_INTERVAL + 2 * RETENTION_SLACK, 5, 0,
                       lambda: cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) == 0),
            "Outdated incident was not purged after the monitor window elapsed"
        )
    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.dualtor_active_standby_toggle_to_random_tor
@pytest.mark.dualtor_active_active_setup_standby_on_random_unselected_tor
@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_drop_count_threshold(testbed_params, setup_counters, duthosts, rand_one_dut_hostname,  # noqa: F811
                              ptfadapter, drop_reason, generate_dropped_packet,  # noqa: F811
                              add_default_route_to_dut):                                  # noqa: F811
    """
    Tests that a single below-threshold drop count burst never gets registered
    as an incident, and therefore never produces a persistent drop record.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _skip_unless_port_counter(setup_counters([drop_reason]))

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
        dst_port = testbed_params["physical_port_map"][rx_port]
        pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)
        # Start from a known incident count so the assertion below can be exact.
        cdc.clear_monitor_incidents(duthost, DROP_COUNTER_NAME, dst_port)

        rand_count = random.randint(1, DROP_COUNT_THRESHOLD - 1)
        baseline = cdc.get_monitor_prev_drop_count(duthost, DROP_COUNTER_NAME, dst_port)
        send_packets(duthost, ptfadapter, pkt, rx_port, count=rand_count)

        # Synchronise on a completed poll. The checks below describe what the monitor did
        # with the traffic, so they are only meaningful once it has actually polled it.
        _wait_for_monitor_poll(duthost, DROP_COUNTER_NAME, dst_port, baseline, rand_count)

        # The incident list is the primary signal. incident_count_threshold is 1 here and
        # the monitor only alerts once the tracked incidents *exceed* it, so a single
        # wrongly recorded incident would never raise an alert and would be invisible to
        # the persistent-drop check on its own.
        pytest_assert(
            cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port) == 0,
            "A burst of {} drops was recorded as an incident even though it is below the "
            "drop_count_threshold of {}".format(rand_count, DROP_COUNT_THRESHOLD)
        )
        pytest_assert(
            _persistent_drop_records_count(duthost, DROP_COUNTER_NAME) - records_count_before == 0,
            "Drop entry was created prematurely for a below-threshold drop count"
        )
    finally:
        disable_counter_monitor(duthost, DROP_COUNTER_NAME)
        disable_global_monitor(duthost)
        duthost.command("sonic-clear fdb all")
        duthost.command("sonic-clear arp")


@pytest.mark.dualtor_active_standby_toggle_to_random_tor
@pytest.mark.dualtor_active_active_setup_standby_on_random_unselected_tor
@pytest.mark.parametrize("drop_reason", ["DIP_LINK_LOCAL"])
def test_incident_detection_threshold(testbed_params, setup_counters, duthosts,  # noqa: F811
                                      rand_one_dut_hostname,
                                      drop_reason, generate_dropped_packet,  # noqa: F811
                                      add_default_route_to_dut, ptfadapter):                       # noqa: F811
    """
    Tests that persistent drops are only reported once the number of incidents
    within the configured window exceeds incident_count_threshold.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _skip_unless_port_counter(setup_counters([drop_reason]))
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
        dst_port = testbed_params["physical_port_map"][rx_port]
        pkt = generate_dropped_packet(rx_port, src_ip, LINK_LOCAL_IP)

        records_count_before = _persistent_drop_records_count(duthost, DROP_COUNTER_NAME)
        # The alert fires on the total number of tracked incidents, so a leftover incident
        # from an earlier run would move the alert to an earlier burst. Start from zero so
        # the per-burst expectations below are exact.
        cdc.clear_monitor_incidents(duthost, DROP_COUNTER_NAME, dst_port)

        burst = drop_count_threshold + 1
        for i in range(INCIDENT_COUNT_THRESHOLD + 1):
            baseline = cdc.get_monitor_prev_drop_count(duthost, DROP_COUNTER_NAME, dst_port)
            send_packets(duthost, ptfadapter, pkt, rx_port, count=burst)

            # Each burst only becomes a separate incident once its own poll has processed
            # it. Waiting for that poll both paces the loop and makes the checks below
            # describe a completed poll rather than an arbitrary moment in the cycle.
            _wait_for_monitor_poll(duthost, DROP_COUNTER_NAME, dst_port, baseline, burst)

            if i < INCIDENT_COUNT_THRESHOLD:
                incident_count = cdc.get_incident_count(duthost, DROP_COUNTER_NAME, dst_port)
                pytest_assert(
                    incident_count == i + 1,
                    "Expected exactly {} tracked incidents after {} bursts, got {}"
                    .format(i + 1, i + 1, incident_count)
                )
                # Checking after every completed poll, including the one that brings the
                # count up to incident_count_threshold, is what pins the alert to the
                # burst that exceeds the threshold instead of the one that reaches it.
                pytest_assert(
                    (_persistent_drop_records_count(duthost, DROP_COUNTER_NAME)
                     - records_count_before) == 0,
                    "Drop entry was created after {} incidents, which does not exceed the "
                    "incident_count_threshold of {}".format(i + 1, INCIDENT_COUNT_THRESHOLD)
                )

        # The final burst is the first to take the tracked incidents past the threshold, so
        # the alert must appear now and must be new.
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
