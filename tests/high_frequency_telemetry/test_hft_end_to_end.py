import logging

import pytest

from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
)
from tests.high_frequency_telemetry.utilities import build_expected_series

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]


@pytest.mark.hft_requirements(
    CounterObjectType.PORT, counter="IF_IN_OCTETS"
)
def test_hft_end_to_end_influxdb(
        hft_influxdb, skip_unsupported_hft_test):
    """Smoke-test the daemon-to-OTEL-to-InfluxDB HFT data path."""
    ports = skip_unsupported_hft_test["objects"][:2]
    counters = ["IF_IN_OCTETS"]

    hft_influxdb.profile.create("PORT", ports, counters, poll_interval=10_000)
    expected = build_expected_series(CounterObjectType.PORT, ports, counters)
    stats = hft_influxdb.wait_and_validate(expected, 10_000, min_points=100, timeout=45)
    logger.info("Validated end-to-end HFT series: %s", stats)
