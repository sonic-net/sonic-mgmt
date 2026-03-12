"""
Example test demonstrating DB (Database) reporter usage for historical analysis.

This example shows how to use the telemetry framework with the DB reporter
to emit metrics for historical analysis and trend tracking. The DB reporter
is ideal for capturing test completion results and performance measurements.
"""

import pytest
from tests.common.telemetry import (
    METRIC_LABEL_DEVICE_ID,
    METRIC_LABEL_DEVICE_PORT_ID
)
from tests.common.telemetry.metrics.device import DevicePortMetrics


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_db_reporter_with_device_port_metrics(db_reporter):
    """Example test using DB reporter for historical port performance analysis.

    This test demonstrates:
    1. Using DB reporter to collect final test results
    2. Recording port metrics at the end of a test run
    3. Capturing test completion status with performance measurements
    4. Exporting metrics to local files for database upload

    Args:
        db_reporter: pytest fixture providing DB reporter for historical analysis
    """
    # Define device context for the test
    device_labels = {
        METRIC_LABEL_DEVICE_ID: "dut-01",
        METRIC_LABEL_DEVICE_PORT_ID: "Ethernet0"
    }

    # Simulate test execution and capture final results
    # In a real test, this would be the actual measured performance

    # Create port metrics collection for final results
    port_metrics = DevicePortMetrics(reporter=db_reporter, labels=device_labels)

    # Record final throughput results (peak performance achieved)
    port_metrics.rx_bps.record(9850000000)  # Peak RX: 9.85 Gbps
    port_metrics.tx_bps.record(9850000000)  # Peak TX: 9.85 Gbps

    # Record final utilization measurements
    port_metrics.rx_util.record(98.5)  # Peak RX utilization: 98.5%
    port_metrics.tx_util.record(98.5)  # Peak TX utilization: 98.5%

    # Record total packet counts during test
    port_metrics.rx_ok.record(15000000)  # Total successful RX packets
    port_metrics.tx_ok.record(15000000)  # Total successful TX packets

    # Record error summary (critical for test validation)
    port_metrics.rx_err.record(0)   # No RX errors - test passed
    port_metrics.tx_err.record(0)   # No TX errors - test passed
    port_metrics.rx_drop.record(0)  # No drops - test passed
    port_metrics.tx_drop.record(0)  # No drops - test passed

    # Record any overrun events during test
    port_metrics.rx_overrun.record(0)  # No RX buffer overruns
    port_metrics.tx_overrun.record(0)  # No TX buffer overruns

    # Export final results to local file for database upload
    # This creates a file that will be processed for historical analysis
    db_reporter.report()

    # Verify metrics were collected for export
    assert db_reporter.get_recorded_metrics_count() == 0  # Should be 0 after reporting


def test_db_reporter_performance_test_results(db_reporter):
    """Example test capturing performance test completion results.

    This demonstrates how to capture comprehensive test results
    including test parameters, achieved performance, and validation status.

    Args:
        db_reporter: pytest fixture providing DB reporter for historical analysis
    """
    # Define test context with detailed labels
    test_labels = {
        METRIC_LABEL_DEVICE_ID: "performance-dut-02",
        METRIC_LABEL_DEVICE_PORT_ID: "Ethernet0",
        # Test parameters for historical trend analysis
        "test.params.topology": "t0",
        "test.params.frame_size": "64",
        "test.params.traffic_duration": "600",
        "test.params.traffic_rate": "100",
        "test.result.status": "PASSED",
        "test.result.test_type": "line_rate_performance"
    }

    # Create port metrics for test completion results
    port_metrics = DevicePortMetrics(reporter=db_reporter, labels=test_labels)

    # Record achieved performance results
    # These are the final measurements at test completion
    achieved_rx_bps = 9999000000  # Near line-rate: 9.999 Gbps
    achieved_tx_bps = 9999000000  # Near line-rate: 9.999 Gbps

    port_metrics.rx_bps.record(achieved_rx_bps)
    port_metrics.tx_bps.record(achieved_tx_bps)
    port_metrics.rx_util.record(99.99)  # 99.99% utilization achieved
    port_metrics.tx_util.record(99.99)  # 99.99% utilization achieved

    # Record packet statistics for the entire test run
    total_test_packets = 50000000  # 50M packets transmitted
    port_metrics.rx_ok.record(total_test_packets)      # All received successfully
    port_metrics.tx_ok.record(total_test_packets)      # All transmitted successfully

    # Test validation: no errors should occur during performance test
    port_metrics.rx_err.record(0)        # Zero errors = test passed
    port_metrics.tx_err.record(0)        # Zero errors = test passed
    port_metrics.rx_drop.record(0)       # Zero drops = test passed
    port_metrics.tx_drop.record(0)       # Zero drops = test passed
    port_metrics.rx_overrun.record(0)    # No buffer issues
    port_metrics.tx_overrun.record(0)    # No buffer issues

    # Export test completion results for historical tracking
    db_reporter.report()

    assert db_reporter.get_recorded_metrics_count() == 0


def test_db_reporter_stress_test_summary(db_reporter):
    """Example test capturing stress test results with error analysis.

    This demonstrates how to capture results from a stress test
    where some errors are expected and need to be tracked historically.

    Args:
        db_reporter: pytest fixture providing DB reporter for historical analysis
    """
    # Define stress test context
    stress_test_labels = {
        METRIC_LABEL_DEVICE_ID: "stress-dut-03",
        METRIC_LABEL_DEVICE_PORT_ID: "Ethernet0",
        "test.params.test_type": "port_stress",
        "test.params.stress_duration": "7200",  # 2 hour stress test
        "test.params.oversubscription_ratio": "2.0",
        "test.params.burst_pattern": "enabled",
        "test.result.status": "PASSED",
        "test.result.error_threshold": "0.001"  # 0.001% error threshold
    }

    # Create metrics collection for stress test results
    port_metrics = DevicePortMetrics(reporter=db_reporter, labels=stress_test_labels)

    # Record stress test performance (lower than line rate due to stress conditions)
    port_metrics.rx_bps.record(8500000000)  # 8.5 Gbps under stress
    port_metrics.tx_bps.record(8500000000)  # 8.5 Gbps under stress
    port_metrics.rx_util.record(85.0)       # 85% utilization
    port_metrics.tx_util.record(85.0)       # 85% utilization

    # Record packet counts during 2-hour stress test
    successful_rx = 199995000         # 99.9975% success rate
    successful_tx = 199995000         # 99.9975% success rate

    port_metrics.rx_ok.record(successful_rx)
    port_metrics.tx_ok.record(successful_tx)

    # Record stress-induced errors (within acceptable threshold)
    error_count = 5000  # 0.0025% error rate - within threshold
    port_metrics.rx_err.record(error_count)
    port_metrics.tx_err.record(error_count)

    # Some drops expected under stress conditions
    port_metrics.rx_drop.record(2000)  # Minimal drops
    port_metrics.tx_drop.record(2000)  # Minimal drops

    # Overrun events during burst periods (acceptable for stress test)
    port_metrics.rx_overrun.record(10)  # Few overruns during bursts
    port_metrics.tx_overrun.record(10)  # Few overruns during bursts

    # Export stress test results for trend analysis
    # This data helps track device stability over time
    db_reporter.report()

    assert db_reporter.get_recorded_metrics_count() == 0
