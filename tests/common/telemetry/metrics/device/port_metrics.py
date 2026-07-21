"""
Device port metrics collection for network interface monitoring.

This module provides a comprehensive set of metrics for monitoring
network port performance, utilization, and error conditions.
"""

from typing import Optional, Dict, List
from ...base import MetricCollection, Reporter, MetricDefinition
from ...constants import (
    METRIC_NAME_PORT_RX_BPS, METRIC_NAME_PORT_TX_BPS,
    METRIC_NAME_PORT_RX_UTIL, METRIC_NAME_PORT_TX_UTIL,
    METRIC_NAME_PORT_RX_OK, METRIC_NAME_PORT_TX_OK,
    METRIC_NAME_PORT_RX_ERR, METRIC_NAME_PORT_TX_ERR,
    METRIC_NAME_PORT_RX_DROP, METRIC_NAME_PORT_TX_DROP,
    METRIC_NAME_PORT_RX_OVERRUN, METRIC_NAME_PORT_TX_OVERRUN,
    UNIT_BYTES_PER_SECOND, UNIT_PERCENT, UNIT_COUNT
)


class DevicePortMetrics(MetricCollection):
    """
    Comprehensive port metrics collection for network interface monitoring.

    Provides metrics for throughput, utilization, packet counts, errors,
    drops, and overruns for both RX and TX directions.
    """

    # Metrics definitions using MetricDefinition for clean, structured definitions
    METRICS_DEFINITIONS: List[MetricDefinition] = [
        # Throughput metrics
        MetricDefinition("rx_bps", METRIC_NAME_PORT_RX_BPS, "Port RX (bps)", UNIT_BYTES_PER_SECOND),
        MetricDefinition("tx_bps", METRIC_NAME_PORT_TX_BPS, "Port TX (bps)", UNIT_BYTES_PER_SECOND),

        # Utilization metrics
        MetricDefinition("rx_util", METRIC_NAME_PORT_RX_UTIL, "Port RX util (%)", UNIT_PERCENT),
        MetricDefinition("tx_util", METRIC_NAME_PORT_TX_UTIL, "Port TX util (%)", UNIT_PERCENT),

        # Success packet counters
        MetricDefinition("rx_ok", METRIC_NAME_PORT_RX_OK, "Port RX packets", UNIT_COUNT),
        MetricDefinition("tx_ok", METRIC_NAME_PORT_TX_OK, "Port TX packets", UNIT_COUNT),

        # Error counters
        MetricDefinition("rx_err", METRIC_NAME_PORT_RX_ERR, "Port RX error packets", UNIT_COUNT),
        MetricDefinition("tx_err", METRIC_NAME_PORT_TX_ERR, "Port TX error packets", UNIT_COUNT),

        # Drop counters
        MetricDefinition("rx_drop", METRIC_NAME_PORT_RX_DROP, "Port RX dropped packets", UNIT_COUNT),
        MetricDefinition("tx_drop", METRIC_NAME_PORT_TX_DROP, "Port TX dropped packets", UNIT_COUNT),

        # Overrun counters
        MetricDefinition("rx_overrun", METRIC_NAME_PORT_RX_OVERRUN, "Port RX overrun events", UNIT_COUNT),
        MetricDefinition("tx_overrun", METRIC_NAME_PORT_TX_OVERRUN, "Port TX overrun events", UNIT_COUNT),
    ]

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        """
        Initialize device port metrics collection.

        Args:
            reporter: Reporter instance for all port metrics
            labels: Common labels (should include device.port.id)
        """
        super().__init__(reporter, labels)
