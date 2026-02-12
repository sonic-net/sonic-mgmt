import pytest
import logging
import time
import os

from tests.common.helpers.assertions import pytest_assert
from tests.high_frequency_telemetry.utilities import (
    setup_hft_profile,
    setup_hft_group,
    cleanup_hft_config,
    get_available_ports,
    start_countersyncd_otel,
    install_otel_collector_config,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

def enable_otel_collector(duthost, timeout=60):
    """
    Enable the OpenTelemetry collector on the DUT and wait until the otel container is running.
    """
    logger.info("Enabling OpenTelemetry collector...")
    duthost.shell("sudo config feature state otel enabled", module_ignore_errors=False)

    end_time = time.time() + timeout
    while time.time() < end_time:
        result = duthost.shell(
            'docker ps --format "{{.Names}}" | grep -w otel',
            module_ignore_errors=True
        )
        if result["rc"] == 0 and result["stdout"].strip() == "otel":
            return True
        time.sleep(2)
    pytest_assert(False, "otel container did not become ready in time")


def test_hft_end_to_end_influxdb(duthosts, enum_rand_one_per_hwsku_hostname, disable_flex_counters, tbinfo, ptfhost):
    """
    Test end-to-end high frequency telemetry with OpenTelemetry collector exporting to InfluxDB.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    profile_name = "port_profile"
    group_name = "PORT"

    # Install and enable OpenTelemetry collector with InfluxDB configuration
    yaml_path = os.path.join(os.path.dirname(__file__), "otel_collector_influxdb.yaml")
    with open(yaml_path, "r") as f:
        yaml_text = f.read()
    install_otel_collector_config(duthost, tbinfo, yaml_text, restart=True)
    enable_otel_collector(duthost)

    # Get available ports from topology (try for 2 ports, min 1 required)
    test_ports = get_available_ports(duthost, tbinfo, desired_ports=2,
                                     min_ports=1)

    logger.info(f"Using ports for testing: {test_ports}")

    try:
        # Step 1: Set up high frequency telemetry profile
        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=10000,
            stream_state="enabled"  # Changed from "disabled" to "enabled"
        )

        # Step 2: Configure port group with specific ports and counters
        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=test_ports,
            object_counters=["IF_IN_OCTETS"]
        )

        logger.info("High frequency telemetry configuration completed")

        # Step 3: Start countersyncd and export to OpenTelemetry collector
        start_countersyncd_otel(duthost, stats_interval=60)
        time.sleep(20)

        # Step 4: Query InfluxDB on PTF to confirm metrics arrived
        flux_query = (
            'from(bucket:"home")'
            ' |> range(start:-10m)'
            ' |> filter(fn: (r) => r["_measurement"] =~ /telemetry|hft|counter/i)'
            ' |> limit(n:1)'
        )

        influx_cmd = (
            'docker exec -i influxdb '
            'influx query '
            '--org docs '
            '--token mytoken123456789 '
            f'--raw "{flux_query}"'
        )

        result = ptfhost.shell(influx_cmd, module_ignore_errors=True)
        pytest_assert(
            result["rc"] == 0 and result.get("stdout", "").strip(),
            "No metrics found in InfluxDB (query returned empty)"
        )

    finally:
        cleanup_hft_config(duthost, profile_name)
