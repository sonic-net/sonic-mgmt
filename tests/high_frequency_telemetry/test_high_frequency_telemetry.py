import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
    get_support_counter_list,
)
from tests.high_frequency_telemetry.utilities import (
    ContinuousTraffic,
    build_expected_series,
    cleanup_hft_config,
    get_available_ports,
    get_configured_buffer_pools,
    get_configured_buffer_queue_objects,
    get_configured_queue_objects,
    setup_hft_config,
    setup_hft_stream_state,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

DEFAULT_POLL_INTERVAL_US = 10_000


def _require_port_counter(duthost, counter_name="IF_IN_OCTETS"):
    supported = get_support_counter_list(duthost, CounterObjectType.PORT)
    if counter_name not in supported:
        pytest.skip(f"{counter_name} is not supported on this platform")


def _configure_and_validate(duthost, sink, profile_name, group_name,
                            counter_type, objects, counters,
                            poll_interval_us=DEFAULT_POLL_INTERVAL_US,
                            min_points=100, timeout=45,
                            interval_tolerance=0.05,
                            validate_cadence=True):
    setup_hft_config(
        duthost,
        profile_name,
        group_name,
        objects,
        counters,
        poll_interval=poll_interval_us,
        stream_state="enabled",
    )
    expected = build_expected_series(counter_type, objects, counters)
    stats = sink.wait_and_validate(
        expected,
        poll_interval_us,
        min_points=min_points,
        timeout=timeout,
        interval_tolerance=interval_tolerance,
        validate_cadence=validate_cadence,
    )
    pytest_assert(
        len(stats) == len(expected),
        f"Validated {len(stats)} series, expected {len(expected)}",
    )
    return expected, stats


def test_hft_full_ingress_priority_group_counters(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb):
    """Verify every supported counter for every configured ingress PG."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "ingress_pg_profile"
    pg_objects = get_configured_buffer_queue_objects(duthost)
    counters = get_support_counter_list(
        duthost, CounterObjectType.INGRESS_PRIORITY_GROUP
    )
    if not pg_objects:
        pytest.skip("No ingress priority groups found in COUNTERS_DB")
    if not counters:
        pytest.skip("No ingress priority group counters supported on this platform")

    try:
        _configure_and_validate(
            duthost,
            hft_influxdb,
            profile_name,
            "INGRESS_PRIORITY_GROUP",
            CounterObjectType.INGRESS_PRIORITY_GROUP,
            pg_objects,
            counters,
            min_points=20,
            timeout=90,
            validate_cadence=False,
        )
    finally:
        cleanup_hft_config(
            duthost, profile_name, ["INGRESS_PRIORITY_GROUP"]
        )


def test_hft_full_buffer_pool_counters(
        request, duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify every supported counter for every configured buffer pool."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    counters = get_support_counter_list(duthost, CounterObjectType.BUFFER_POOL)
    if not counters:
        pytest.skip("No buffer pool counters supported on this platform")
    buffer_pools = get_configured_buffer_pools(duthost)
    if not buffer_pools:
        pytest.skip("No buffer pools found in COUNTERS_DB")
    profile_name = "buffer_pool_profile"
    hft_influxdb = request.getfixturevalue("hft_influxdb")

    try:
        _configure_and_validate(
            duthost,
            hft_influxdb,
            profile_name,
            "BUFFER_POOL",
            CounterObjectType.BUFFER_POOL,
            buffer_pools,
            counters,
        )
    finally:
        cleanup_hft_config(duthost, profile_name, ["BUFFER_POOL"])


@pytest.mark.skip(
    reason="Target platforms do not support multiple object types in one HFT session"
)
def test_hft_full_counters():
    """Reserved for platforms that support mixed object types in one session."""


def test_hft_full_port_counters(duthosts, enum_rand_one_per_hwsku_hostname,
                                tbinfo, hft_influxdb):
    """Verify every supported port counter for every available port."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_port_counter(duthost)
    profile_name = "full_port_counter_profile"
    ports = get_available_ports(duthost, tbinfo, desired_ports=None, min_ports=1)
    counters = get_support_counter_list(duthost, CounterObjectType.PORT)
    if not counters:
        pytest.skip("No port counters supported on this platform")

    try:
        _configure_and_validate(
            duthost,
            hft_influxdb,
            profile_name,
            "PORT",
            CounterObjectType.PORT,
            ports,
            counters,
            timeout=90,
        )
    finally:
        cleanup_hft_config(duthost, profile_name, ["PORT"])


def test_hft_disabled_stream(duthosts, enum_rand_one_per_hwsku_hostname,
                             tbinfo, hft_influxdb):
    """Verify enable, disable, and re-enable using InfluxDB watermarks."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_port_counter(duthost)
    profile_name = "state_transition_profile"
    ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)
    counters = ["IF_IN_OCTETS"]
    expected = build_expected_series(CounterObjectType.PORT, ports, counters)

    try:
        setup_hft_config(
            duthost,
            profile_name,
            "PORT",
            ports,
            counters,
            poll_interval=DEFAULT_POLL_INTERVAL_US,
            stream_state="disabled",
        )

        setup_hft_stream_state(duthost, profile_name, "enabled")
        hft_influxdb.wait_and_validate(
            expected, DEFAULT_POLL_INTERVAL_US, min_points=100, timeout=45
        )

        setup_hft_stream_state(duthost, profile_name, "disabled")
        disabled_watermark = hft_influxdb.assert_no_new_points(expected)

        setup_hft_stream_state(duthost, profile_name, "enabled")
        hft_influxdb.wait_for_new_points(
            expected, disabled_watermark, timeout=45
        )
    finally:
        cleanup_hft_config(duthost, profile_name, ["PORT"])


def test_hft_config_deletion_stream(
        duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, hft_influxdb):
    """Verify create, delete, and recreate using InfluxDB watermarks."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_port_counter(duthost)
    profile_name = "config_deletion_profile"
    ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)
    counters = ["IF_IN_OCTETS"]
    expected = build_expected_series(CounterObjectType.PORT, ports, counters)

    try:
        setup_hft_config(
            duthost,
            profile_name,
            "PORT",
            ports,
            counters,
            poll_interval=DEFAULT_POLL_INTERVAL_US,
            stream_state="enabled",
        )
        hft_influxdb.wait_and_validate(
            expected, DEFAULT_POLL_INTERVAL_US, min_points=100, timeout=45
        )

        cleanup_hft_config(duthost, profile_name, ["PORT"])
        deleted_watermark = hft_influxdb.assert_no_new_points(expected)

        setup_hft_config(
            duthost,
            profile_name,
            "PORT",
            ports,
            counters,
            poll_interval=DEFAULT_POLL_INTERVAL_US,
            stream_state="enabled",
        )
        hft_influxdb.wait_for_new_points(
            expected, deleted_watermark, timeout=45
        )
    finally:
        cleanup_hft_config(duthost, profile_name, ["PORT"])


def test_hft_poll_interval_validation(
        duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, hft_influxdb):
    """Verify the 1ms poll interval from source timestamps and CPS."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_port_counter(duthost)
    poll_interval_us = 1_000
    profile_name = f"poll_interval_profile_{poll_interval_us}"
    ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)

    try:
        _configure_and_validate(
            duthost,
            hft_influxdb,
            profile_name,
            "PORT",
            CounterObjectType.PORT,
            ports,
            ["IF_IN_OCTETS"],
            poll_interval_us=poll_interval_us,
            min_points=100,
            timeout=30,
        )
    finally:
        cleanup_hft_config(duthost, profile_name, ["PORT"])


def test_hft_port_shutdown_stream(
        duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, ptfadapter,
        hft_influxdb):
    """Verify counter values grow when up, stay stable when down, and recover."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_port_counter(duthost)
    profile_name = "port_shutdown_profile"
    candidate_ports = get_available_ports(
        duthost, tbinfo, desired_ports=None, min_ports=1
    )
    down_ports = set(
        duthost.interface_facts(up_ports=candidate_ports)["ansible_facts"]
        ["ansible_interface_link_down_ports"]
    )
    oper_up_ports = [port for port in candidate_ports if port not in down_ports]
    if not oper_up_ports:
        pytest.skip("No operationally up, PTF-mapped port is available")
    test_port = oper_up_ports[0]
    ptf_port_index = duthost.get_extended_minigraph_facts(tbinfo)[
        "minigraph_ptf_indices"
    ][test_port]
    traffic = ContinuousTraffic(
        ptfadapter, ptf_port_index, duthost.facts["router_mac"]
    )
    expected = build_expected_series(
        CounterObjectType.PORT, [test_port], ["IF_IN_OCTETS"]
    )

    try:
        setup_hft_config(
            duthost,
            profile_name,
            "PORT",
            [test_port],
            ["IF_IN_OCTETS"],
            poll_interval=DEFAULT_POLL_INTERVAL_US,
            stream_state="enabled",
        )

        # The selected port is already operationally up. Start traffic and
        # validate immediately so all transition checks fit within the active
        # hardware streaming window.
        traffic.start()
        up_stats = hft_influxdb.wait_and_validate(
            expected, DEFAULT_POLL_INTERVAL_US, min_points=100, timeout=45
        )
        series_key = next(iter(up_stats))
        pytest_assert(
            up_stats[series_key]["last_value"]
            > up_stats[series_key]["first_value"],
            f"Counter did not increase while {test_port} was up",
        )

        duthost.shell(f"config interface shutdown {test_port}")
        pytest_assert(
            wait_until(
                15, 1, 0,
                lambda: not duthost.is_interface_status_up(test_port),
            ),
            f"{test_port} did not become operationally down",
        )
        down_watermark = hft_influxdb.assert_no_new_points(expected)
        down_values = hft_influxdb.latest(expected)

        duthost.shell(f"config interface startup {test_port}")
        pytest_assert(
            wait_until(15, 1, 0, duthost.is_interface_status_up, test_port),
            f"{test_port} did not recover operationally",
        )
        hft_influxdb.wait_for_new_points(
            expected, down_watermark, timeout=45
        )
        hft_influxdb.wait_for_values_to_increase(
            expected, down_values, timeout=45
        )
        traffic.stop()
        pytest_assert(traffic.packet_count > 0, "No PTF traffic was transmitted")
        pytest_assert(
            not traffic.errors,
            f"PTF traffic sender errors: {traffic.errors[:10]}",
        )
    finally:
        traffic.stop()
        duthost.shell(
            f"config interface startup {test_port}", module_ignore_errors=True
        )
        cleanup_hft_config(duthost, profile_name, ["PORT"])


def test_hft_full_queue_counters(duthosts, enum_rand_one_per_hwsku_hostname,
                                 hft_influxdb):
    """Verify every supported counter for every configured queue."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "queue_profile"
    queue_objects = get_configured_queue_objects(duthost)
    counters = get_support_counter_list(duthost, CounterObjectType.QUEUE)
    if not queue_objects:
        pytest.skip("No queue objects found in COUNTERS_DB")
    if not counters:
        pytest.skip("No queue counters supported on this platform")

    try:
        _configure_and_validate(
            duthost,
            hft_influxdb,
            profile_name,
            "QUEUE",
            CounterObjectType.QUEUE,
            queue_objects,
            counters,
            min_points=100,
            timeout=120,
            interval_tolerance=0.10,
        )
    finally:
        cleanup_hft_config(duthost, profile_name, ["QUEUE"])
