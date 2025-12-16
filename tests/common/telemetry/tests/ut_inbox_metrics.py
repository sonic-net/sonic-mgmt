"""
Tests for telemetry metrics classes using mock reporters.

This module focuses on testing the inbox metric collections
using mock reporters to verify correct value recording, label passing, and
metric type identification.

Each metric collection test follows the pattern:
1. Initialize collection with mock reporter
2. Record values for each metric attribute
3. Validate recorded metrics match expected JSON baseline
"""

import pytest

# Import the telemetry framework
from common.telemetry import (
    DevicePortMetrics, DevicePSUMetrics, DeviceQueueMetrics,
    DeviceTemperatureMetrics, DeviceFanMetrics
)

# Import test utilities
from .common_utils import validate_recorded_metrics


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_device_port_metrics(mock_reporter):
    """Test DevicePortMetrics collection records all metrics correctly."""
    # Create port metrics collection
    port_metrics = DevicePortMetrics(
        reporter=mock_reporter,
        labels={"device.id": "spine-01", "device.port.id": "Ethernet8"}
    )

    # Record each metric value directly
    port_metrics.tx_util.record(45.2)
    port_metrics.rx_util.record(32.8)
    port_metrics.tx_bps.record(1200000000)
    port_metrics.rx_bps.record(1000000000)
    port_metrics.tx_ok.record(12345678)
    port_metrics.rx_ok.record(10987654)
    port_metrics.tx_err.record(3)
    port_metrics.rx_err.record(5)
    port_metrics.tx_drop.record(12)
    port_metrics.rx_drop.record(8)
    port_metrics.tx_overrun.record(0)
    port_metrics.rx_overrun.record(1)

    # Validate results using common function
    validate_recorded_metrics(mock_reporter, "device_port_metrics")


def test_device_psu_metrics(mock_reporter):
    """Test DevicePSUMetrics collection records all metrics correctly."""
    # Create PSU metrics collection
    psu_metrics = DevicePSUMetrics(
        reporter=mock_reporter,
        labels={"device.id": "leaf-02", "device.psu.id": "PSU-1"}
    )

    # Record each metric value directly
    psu_metrics.voltage.record(12.1)
    psu_metrics.current.record(18.5)
    psu_metrics.power.record(222.0)
    psu_metrics.status.record(1.0)
    psu_metrics.led.record(1.0)

    # Validate results using common function
    validate_recorded_metrics(mock_reporter, "device_psu_metrics")


def test_device_queue_metrics(mock_reporter):
    """Test DeviceQueueMetrics collection records all metrics correctly."""
    # Create queue metrics collection
    queue_metrics = DeviceQueueMetrics(
        reporter=mock_reporter,
        labels={"device.id": "dut-01", "device.queue.id": "UC0"}
    )

    # Record each metric value directly
    queue_metrics.watermark_bytes.record(1048576)

    # Validate results using common function
    validate_recorded_metrics(mock_reporter, "device_queue_metrics")


def test_device_temperature_metrics(mock_reporter):
    """Test DeviceTemperatureMetrics collection records all metrics correctly."""
    # Create temperature metrics collection
    temp_metrics = DeviceTemperatureMetrics(
        reporter=mock_reporter,
        labels={"device.id": "spine-01", "device.sensor.id": "CPU"}
    )

    # Record each metric value directly
    temp_metrics.reading.record(42.5)
    temp_metrics.high_th.record(85.0)
    temp_metrics.low_th.record(0.0)
    temp_metrics.crit_high_th.record(95.0)
    temp_metrics.crit_low_th.record(-10.0)
    temp_metrics.warning.record(0.0)

    # Validate results using common function
    validate_recorded_metrics(mock_reporter, "device_temperature_metrics")


def test_device_fan_metrics(mock_reporter):
    """Test DeviceFanMetrics collection records all metrics correctly."""
    # Create fan metrics collection
    fan_metrics = DeviceFanMetrics(
        reporter=mock_reporter,
        labels={"device.id": "leaf-01", "device.fan.id": "Fan-1"}
    )

    # Record each metric value directly
    fan_metrics.speed.record(8500.0)
    fan_metrics.status.record(1.0)

    # Validate results using common function
    validate_recorded_metrics(mock_reporter, "device_fan_metrics")


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__])
