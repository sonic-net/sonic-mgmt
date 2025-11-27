"""
Device PSU metrics collection for power supply monitoring.

This module provides metrics for monitoring power supply unit (PSU)
performance, including voltage, current, power, status, and LED indicators.
"""

from typing import Optional, Dict, List
from ...base import MetricCollection, Reporter, MetricDefinition
from ...constants import (
    METRIC_NAME_PSU_VOLTAGE, METRIC_NAME_PSU_CURRENT, METRIC_NAME_PSU_POWER,
    METRIC_NAME_PSU_STATUS, METRIC_NAME_PSU_LED,
    UNIT_VOLTS, UNIT_AMPERES, UNIT_WATTS, UNIT_COUNT
)


class DevicePSUMetrics(MetricCollection):
    """
    Comprehensive PSU metrics collection for power supply monitoring.

    Provides metrics for electrical measurements (voltage, current, power)
    and operational status indicators (status, LED state).
    """

    # Metrics definitions using MetricDefinition for clean, structured definitions
    METRICS_DEFINITIONS: List[MetricDefinition] = [
        # Electrical measurements
        MetricDefinition("voltage", METRIC_NAME_PSU_VOLTAGE, "PSU output voltage (V)", UNIT_VOLTS),
        MetricDefinition("current", METRIC_NAME_PSU_CURRENT, "PSU output current (A)", UNIT_AMPERES),
        MetricDefinition("power", METRIC_NAME_PSU_POWER, "PSU output power (W)", UNIT_WATTS),

        # Status indicators
        MetricDefinition("status", METRIC_NAME_PSU_STATUS, "PSU operational status (0=error, 1=ok)", UNIT_COUNT),
        MetricDefinition(
            "led", METRIC_NAME_PSU_LED, "PSU LED indicator state (0=off, 1=green, 2=amber, 3=red)", UNIT_COUNT
        ),
    ]

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        """
        Initialize device PSU metrics collection.

        Args:
            reporter: Reporter instance for all PSU metrics
            labels: Common labels (should include device.psu.id)
        """
        super().__init__(reporter, labels)
