"""
Gauge metric implementation for the SONiC telemetry framework.

Gauge metrics represent a value that can go up or down over time,
such as temperature, utilization percentages, or current measurements.
"""

from typing import Dict, Optional, Callable
from ..base import Metric, Reporter, MetricDataEntry
from ..constants import METRIC_TYPE_GAUGE


class GaugeMetric(Metric):
    """
    Gauge metric implementation.

    Gauges represent instantaneous values that can increase or decrease,
    like temperature readings, utilization percentages, or queue depths.
    """

    def __init__(self, name: str, description: str, unit: str, reporter: Reporter,
                 value_convertor: Callable[[str], float] = None,
                 common_labels: Optional[Dict[str, str]] = None):
        """
        Initialize gauge metric.

        Args:
            name: Metric name in OpenTelemetry format
            description: Human-readable description
            unit: Unit of measurement (e.g., 'celsius', 'percent', 'bytes')
            reporter: Reporter instance to send measurements to
            common_labels: Common labels to apply to all measurements of this metric
        """
        super().__init__(METRIC_TYPE_GAUGE, name, description, unit, reporter, value_convertor, common_labels)

    def record(self, value: float, additional_labels: Optional[Dict[str, str]] = None):
        """
        Record a measurement for this metric.

        Args:
            value: Measured value
            additional_labels: Additional labels for this specific measurement
        """
        # Merge labels and create key
        labels_key = self._labels_to_key(additional_labels)

        # Store the value with labels (gauge always overwrites previous value for same labels)
        normalized_value = self._value_convertor(value) if self._value_convertor else value
        self._data[labels_key] = MetricDataEntry(data=normalized_value, labels=additional_labels or {})
