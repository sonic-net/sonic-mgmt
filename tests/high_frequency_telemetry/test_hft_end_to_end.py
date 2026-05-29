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
    stop_countersyncd_otel,
    render_otel_collector_config,
    install_otel_collector_config,
    enable_otel_collector,
    start_influxdb,
    setup_influxdb,
    wait_for_influxdb_data,
    stop_influxdb,
    validate_influxdb_intervals,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

# InfluxDB constants shared between otel collector config and query helpers
INFLUXDB_PORT = 8181
INFLUXDB_BUCKET = "home"


def test_hft_end_to_end_influxdb(duthosts, enum_rand_one_per_hwsku_hostname,
                                 disable_flex_counters, tbinfo, ptfhost):
    """
    End-to-end test for High Frequency Telemetry.

    Flow:
      1. Start InfluxDB 3 on PTF and create the database
      2. Enable the otel container on the DUT
      3. Install the otel-collector config that exports to PTF's InfluxDB
      4. Configure an HFT profile + port group
      5. Start countersyncd with --enable-otel
      6. Poll InfluxDB until metrics arrive (or timeout)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    profile_name = "port_profile"
    group_name = "PORT"

    try:
        # --- Step 1: Start and set up InfluxDB on PTF ---
        start_influxdb(ptfhost, port=INFLUXDB_PORT)
        setup_influxdb(
            ptfhost,
            port=INFLUXDB_PORT,
            bucket=INFLUXDB_BUCKET,
        )

        # --- Step 2: Enable the otel feature (creates the container) ---
        enable_otel_collector(duthost)

        # --- Step 3: Render and install otel collector config, then restart ---
        template_path = os.path.join(
            os.path.dirname(__file__), "otel_collector_influxdb.yaml.j2"
        )
        rendered_config = render_otel_collector_config(
            template_path,
            ptf_ip=tbinfo["ptf_ip"],
            influxdb_bucket=INFLUXDB_BUCKET,
        )
        install_otel_collector_config(duthost, rendered_config)
        duthost.shell("docker restart otel", module_ignore_errors=False)
        time.sleep(5)

        # --- Step 4: Discover ports and configure HFT ---
        test_ports = get_available_ports(
            duthost, tbinfo, desired_ports=2, min_ports=1
        )
        logger.info(f"Using ports for testing: {test_ports}")

        setup_hft_profile(
            duthost=duthost,
            profile_name=profile_name,
            poll_interval=10000,
            stream_state="enabled",
        )

        setup_hft_group(
            duthost=duthost,
            profile_name=profile_name,
            group_name=group_name,
            object_names=test_ports,
            object_counters=["IF_IN_OCTETS"],
        )
        logger.info("High frequency telemetry configuration completed")

        # --- Step 5: Start countersyncd with otel export ---
        start_countersyncd_otel(duthost, stats_interval=60)

        # --- Step 6: Wait for metrics to arrive in InfluxDB ---
        result = wait_for_influxdb_data(
            ptfhost,
            bucket=INFLUXDB_BUCKET,
            port=INFLUXDB_PORT,
            timeout=60,
        )
        pytest_assert(
            result is not None,
            "No metrics found in InfluxDB after waiting 60 seconds",
        )
        logger.info(
            "InfluxDB query returned data:\n"
            f"{result.get('stdout', '')[:500]}"
        )

        # --- Step 7: Accumulate data and validate polling intervals ---
        logger.info("Waiting 30s to accumulate more data points...")
        time.sleep(30)

        interval_result = validate_influxdb_intervals(
            ptfhost,
            bucket=INFLUXDB_BUCKET,
            port=INFLUXDB_PORT,
            expected_interval_ms=10,
            tolerance_low=0.5,
            tolerance_high=1.5,
            avg_tolerance=0.2,
            min_points=10,
        )
        for series, stats in interval_result["groups"].items():
            logger.info(
                "Interval stats for %s: points=%d avg=%.3fms "
                "min=%.3fms max=%.3fms out_of_range=%d",
                series, stats["num_points"], stats["avg_ms"],
                stats["min_ms"], stats["max_ms"],
                stats["out_of_range_count"],
            )
        if interval_result["violations"]:
            for v in interval_result["violations"]:
                logger.warning("Interval violation: %s", v)
        pytest_assert(
            interval_result["passed"],
            "HFT polling interval validation failed: "
            + "; ".join(interval_result["violations"]),
        )
        logger.info("HFT polling interval validation passed")

    finally:
        cleanup_hft_config(duthost, profile_name)
        stop_countersyncd_otel(duthost)
        stop_influxdb(ptfhost)
