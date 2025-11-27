"""
Example test demonstrating TS (TimeSeries) reporter usage for real-time monitoring.

This example shows how to use the telemetry framework with the TS reporter
to emit metrics for real-time monitoring via OpenTelemetry. The TS reporter
is ideal for continuous monitoring during test execution.
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


def test_ts_reporter_with_device_port_metrics(ts_reporter):
    """Example test using TS reporter for real-time port monitoring.

    This test demonstrates:
    1. Setting up device and port labels for metric identification
    2. Creating DevicePortMetrics instance with common labels
    3. Recording various port metrics (throughput, utilization, counters)
    4. Reporting metrics to OpenTelemetry for real-time monitoring

    Args:
        ts_reporter: pytest fixture providing TS reporter for real-time monitoring
    """
    # Skip real report. Don't include in real usage.
    ts_reporter.set_mock_exporter(lambda data: None)

    # Define device context - this identifies which device/port we're monitoring
    device_labels = {
        METRIC_LABEL_DEVICE_ID: "switch-01",
        METRIC_LABEL_DEVICE_PORT_ID: "Ethernet0"
    }

    # Create port metrics collection with device labels automatically applied
    port_metrics = DevicePortMetrics(reporter=ts_reporter, labels=device_labels)

    # Record throughput metrics (bytes per second)
    port_metrics.rx_bps.record(1000000000)  # 1 Gbps RX
    port_metrics.tx_bps.record(850000000)   # 850 Mbps TX

    # Report all recorded metrics to OpenTelemetry
    # This sends the metrics to the OTLP endpoint for real-time monitoring
    ts_reporter.report()

    # Verify metrics were collected (optional validation)
    assert ts_reporter.recorded_metrics_count() == 0  # Should be 0 after reporting


def test_ts_reporter_multiple_ports(ts_reporter):
    """Example test monitoring multiple ports simultaneously.

    This demonstrates how to efficiently monitor multiple network ports
    using the same metrics definitions but different label sets.

    Args:
        ts_reporter: pytest fixture providing TS reporter for real-time monitoring
    """
    # Skip real report. Don't include in real usage.
    ts_reporter.set_mock_exporter(lambda data: None)

    # Monitor multiple ports on the same device
    ports_to_monitor = ["Ethernet0", "Ethernet4", "Ethernet8", "Ethernet12"]

    device_labels = {METRIC_LABEL_DEVICE_ID: "switch-02"}
    port_metrics = DevicePortMetrics(reporter=ts_reporter, labels=device_labels)

    for port_id in ports_to_monitor:
        # Create labels specific to each port
        port_labels = {METRIC_LABEL_DEVICE_PORT_ID: port_id}

        port_metrics.rx_bps.record(9500000000, port_labels)  # 9.5 Gbps
        port_metrics.tx_bps.record(9200000000, port_labels)  # 9.2 Gbps

    # Report all collected metrics at once
    ts_reporter.report()

    # All metrics should be reported
    assert ts_reporter.recorded_metrics_count() == 0


def test_ts_reporter_with_custom_test_labels(ts_reporter):
    """Example showing how to add test-specific labels to metrics.

    This demonstrates adding test parameters and context as labels
    for better metric categorization and analysis.

    Args:
        ts_reporter: pytest fixture providing TS reporter for real-time monitoring
    """
    # Skip real report. Don't include in real usage.
    ts_reporter.set_mock_exporter(lambda data: None)

    # Base device labels
    device_labels = {
        METRIC_LABEL_DEVICE_ID: "switch-03",
        METRIC_LABEL_DEVICE_PORT_ID: "Ethernet0"
    }

    # Add test-specific parameters as labels
    test_context_labels = {
        **device_labels,
        "test.params.topology": "t1",
        "test.params.traffic_pattern": "uniform",
        "test.params.frame_size": "1518",
        "test.params.test_duration": "300"
    }

    # Create port metrics with enhanced labeling
    port_metrics = DevicePortMetrics(reporter=ts_reporter, labels=test_context_labels)

    # Record metrics during a specific test scenario
    port_metrics.rx_bps.record(7500000000)  # 7.5 Gbps during test
    port_metrics.tx_bps.record(7500000000)  # 7.5 Gbps during test

    # Report metrics with test context
    ts_reporter.report()

    assert ts_reporter.recorded_metrics_count() == 0
