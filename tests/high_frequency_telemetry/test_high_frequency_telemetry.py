import logging
import sys

import pytest
from _pytest.outcomes import OutcomeException

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
)
from tests.high_frequency_telemetry.utilities import (
    ContinuousTraffic,
    build_expected_series,
    cleanup_hft_config,
    setup_hft_config,
    setup_hft_stream_state,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

DEFAULT_POLL_INTERVAL_US = 10_000


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


@pytest.mark.hft_requirements(CounterObjectType.QUEUE)
def test_hft_full_queue_counters(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_queue_influxdb,
        skip_unsupported_hft_test):
    """Verify every supported counter for every configured queue."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "queue_profile"
    queue_objects = skip_unsupported_hft_test["objects"]
    counters = skip_unsupported_hft_test["counters"]
    _configure_and_validate(
        duthost,
        hft_queue_influxdb,
        profile_name,
        "QUEUE",
        CounterObjectType.QUEUE,
        queue_objects,
        counters,
        min_points=100,
        timeout=120,
        interval_tolerance=0.10,
    )


@pytest.mark.hft_requirements(CounterObjectType.INGRESS_PRIORITY_GROUP)
def test_hft_full_ingress_priority_group_counters(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb,
        skip_unsupported_hft_test):
    """Verify every supported counter for every configured ingress PG."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "ingress_pg_profile"
    pg_objects = skip_unsupported_hft_test["objects"]
    counters = skip_unsupported_hft_test["counters"]
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


@pytest.mark.hft_requirements(CounterObjectType.BUFFER_POOL)
def test_hft_full_buffer_pool_counters(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb,
        skip_unsupported_hft_test):
    """Verify every supported counter for every configured buffer pool."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    counters = skip_unsupported_hft_test["counters"]
    buffer_pools = skip_unsupported_hft_test["objects"]
    profile_name = "buffer_pool_profile"

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


@pytest.mark.hft_requirements(
    CounterObjectType.PORT, counter="IF_IN_OCTETS"
)
def test_hft_full_port_counters(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb,
        skip_unsupported_hft_test):
    """Verify every supported port counter for every available port."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "full_port_counter_profile"
    ports = skip_unsupported_hft_test["objects"]
    counters = skip_unsupported_hft_test["counters"]

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


@pytest.mark.hft_requirements(
    CounterObjectType.PORT, counter="IF_IN_OCTETS"
)
def test_hft_disabled_stream(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb,
        skip_unsupported_hft_test):
    """Verify enable, disable, and re-enable using InfluxDB watermarks."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "state_transition_profile"
    ports = skip_unsupported_hft_test["objects"][:2]
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


@pytest.mark.hft_requirements(
    CounterObjectType.PORT, counter="IF_IN_OCTETS"
)
def test_hft_config_deletion_stream(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb,
        skip_unsupported_hft_test):
    """Verify create, delete, and recreate using InfluxDB watermarks."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "config_deletion_profile"
    ports = skip_unsupported_hft_test["objects"][:2]
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


@pytest.mark.hft_requirements(
    CounterObjectType.PORT, counter="IF_IN_OCTETS"
)
def test_hft_poll_interval_validation(
        duthosts, enum_rand_one_per_hwsku_hostname, hft_influxdb,
        skip_unsupported_hft_test):
    """Verify the 1ms poll interval from source timestamps and CPS."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    poll_interval_us = 1_000
    profile_name = f"poll_interval_profile_{poll_interval_us}"
    ports = skip_unsupported_hft_test["objects"][:2]

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


@pytest.mark.hft_requirements(
    CounterObjectType.PORT, counter="IF_IN_OCTETS", oper_up_port=True
)
def test_hft_port_shutdown_stream(
        duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, ptfadapter,
        hft_influxdb, skip_unsupported_hft_test):
    """Verify counter values grow when up, stay stable when down, and recover."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_name = "port_shutdown_profile"
    test_port = skip_unsupported_hft_test["objects"][0]
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
        original_error = sys.exc_info()[1]
        first_cleanup_error = None
        traffic.stop()
        try:
            result = duthost.shell(
                f"config interface startup {test_port}",
                module_ignore_errors=True,
            )
            pytest_assert(
                result.get("rc") == 0,
                f"Failed to restore {test_port}: {result}",
            )
            pytest_assert(
                wait_until(
                    15, 1, 0, duthost.is_interface_status_up, test_port
                ),
                f"{test_port} did not recover during cleanup",
            )
        except (Exception, OutcomeException) as error:
            logger.exception("Failed to restore HFT test port %s", test_port)
            first_cleanup_error = error
        try:
            cleanup_hft_config(duthost, profile_name, ["PORT"])
        except (Exception, OutcomeException) as error:
            if first_cleanup_error is None:
                first_cleanup_error = error
        if first_cleanup_error is not None and original_error is None:
            raise first_cleanup_error
