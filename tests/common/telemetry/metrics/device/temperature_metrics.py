"""
Device temperature metrics collection for thermal monitoring.

This module provides metrics for monitoring device temperature sensors,
thermal thresholds, and warning conditions across various components.
"""

from typing import Optional, Dict, List
from ...base import MetricCollection, Reporter, MetricDefinition
from ...constants import (
    METRIC_NAME_TEMPERATURE_READING, METRIC_NAME_TEMPERATURE_HIGH_TH,
    METRIC_NAME_TEMPERATURE_LOW_TH, METRIC_NAME_TEMPERATURE_CRIT_HIGH_TH,
    METRIC_NAME_TEMPERATURE_CRIT_LOW_TH, METRIC_NAME_TEMPERATURE_WARNING,
    UNIT_CELSIUS, UNIT_COUNT
)


class DeviceTemperatureMetrics(MetricCollection):
    """
    Temperature metrics collection for thermal monitoring.

    Provides metrics for current temperature readings, thermal thresholds,
    and warning states across device sensors and components.
    """

    # Metrics definitions using MetricDefinition for clean, structured definitions
    METRICS_DEFINITIONS: List[MetricDefinition] = [
        # Current reading
        MetricDefinition("reading", METRIC_NAME_TEMPERATURE_READING, "Current temperature reading (C)", UNIT_CELSIUS),

        # Threshold values
        MetricDefinition("high_th", METRIC_NAME_TEMPERATURE_HIGH_TH, "High temperature threshold (C)", UNIT_CELSIUS),
        MetricDefinition("low_th", METRIC_NAME_TEMPERATURE_LOW_TH, "Low temperature threshold (C)", UNIT_CELSIUS),
        MetricDefinition(
            "crit_high_th", METRIC_NAME_TEMPERATURE_CRIT_HIGH_TH,
            "Critical high temperature threshold (C)", UNIT_CELSIUS
        ),
        MetricDefinition(
            "crit_low_th", METRIC_NAME_TEMPERATURE_CRIT_LOW_TH,
            "Critical low temperature threshold (C)", UNIT_CELSIUS
        ),

        # Warning state
        MetricDefinition(
            "warning", METRIC_NAME_TEMPERATURE_WARNING, "Temperature warning state (0=normal, 1=warning)", UNIT_COUNT
        ),
    ]

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        """
        Initialize device temperature metrics collection.

        Args:
            reporter: Reporter instance for all temperature metrics
            labels: Common labels (should include device.sensor.id)
        """
        super().__init__(reporter, labels)
