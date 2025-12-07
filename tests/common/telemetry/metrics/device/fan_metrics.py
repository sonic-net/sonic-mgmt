""" Device fan metrics collection for cooling system monitoring.

This module provides metrics for monitoring cooling fan performance,
including speed measurements and operational status indicators.
"""

from typing import Optional, Dict, List
from ...base import MetricCollection, Reporter, MetricDefinition
from ...constants import (
    METRIC_NAME_FAN_SPEED, METRIC_NAME_FAN_STATUS,
    UNIT_PERCENT, UNIT_COUNT
)


class DeviceFanMetrics(MetricCollection):
    """
    Fan metrics collection for cooling system monitoring.

    Provides metrics for fan speed measurements and operational
    status across device cooling systems.
    """

    # Metrics definitions using MetricDefinition for clean, structured definitions
    METRICS_DEFINITIONS: List[MetricDefinition] = [
        MetricDefinition("speed", METRIC_NAME_FAN_SPEED, "Fan speed (%)", UNIT_PERCENT),
        MetricDefinition("presence", METRIC_NAME_FAN_STATUS, "Fan presence status (0=no, 1=yes)", UNIT_COUNT),
        MetricDefinition("status", METRIC_NAME_FAN_STATUS, "Fan operational status (0=N/A, 1=ok, 2=error)", UNIT_COUNT),
    ]

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        """
        Initialize device fan metrics collection.

        Args:
            reporter: Reporter instance for all fan metrics
            labels: Common labels (should include device.fan.id)
        """
        super().__init__(reporter, labels)
