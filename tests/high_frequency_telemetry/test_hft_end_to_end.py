import logging

import pytest

from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
    get_support_counter_list,
)
from tests.high_frequency_telemetry.utilities import (
    build_expected_series,
    cleanup_hft_config,
    get_available_ports,
    setup_hft_config,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_memory_utilization,
]


def test_hft_end_to_end_influxdb(
        duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, hft_influxdb):
    """Smoke-test the daemon-to-OTEL-to-InfluxDB HFT data path."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if "IF_IN_OCTETS" not in get_support_counter_list(
        duthost, CounterObjectType.PORT
    ):
        pytest.skip("IF_IN_OCTETS is not supported on this platform")
    profile_name = "e2e_port_profile"
    ports = get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=1)
    counters = ["IF_IN_OCTETS"]

    try:
        setup_hft_config(
            duthost,
            profile_name,
            "PORT",
            ports,
            counters,
            poll_interval=10_000,
            stream_state="enabled",
        )
        expected = build_expected_series(
            CounterObjectType.PORT, ports, counters
        )
        stats = hft_influxdb.wait_and_validate(
            expected, 10_000, min_points=100, timeout=45
        )
        logger.info("Validated end-to-end HFT series: %s", stats)
    finally:
        cleanup_hft_config(duthost, profile_name, ["PORT"])
