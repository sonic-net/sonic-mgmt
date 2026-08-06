"""
Histogram metric implementation for the SONiC telemetry framework.

Histogram metrics track the distribution of values over time,
useful for measuring latencies, response times, or request sizes.
"""

from typing import List, Optional, Dict
from ..base import HistogramRecordData, Metric, Reporter, MetricDataEntry
from ..constants import METRIC_TYPE_HISTOGRAM


class HistogramMetric(Metric):
    """
    Histogram metric implementation.

    Histograms track the distribution of measured values, providing
    percentiles, averages, and bucket counts for analysis.
    """

    def __init__(self, name: str, description: str, unit: str, reporter: Reporter,
                 buckets: List[float], common_labels: Optional[Dict[str, str]] = None):
        """
        Initialize histogram metric.

        Args:
            name: Metric name in OpenTelemetry format
            description: Human-readable description
            unit: Unit of measurement (e.g., 'seconds', 'milliseconds', 'bytes')
            reporter: Reporter instance to send measurements to
            buckets: Optional bucket boundaries for histogram distribution
            common_labels: Common labels to apply to all measurements of this metric
        """
        super().__init__(METRIC_TYPE_HISTOGRAM, name, description, unit, reporter, None, common_labels)
        self.buckets = buckets

    def record(self, value: float, additional_labels: Optional[Dict[str, str]] = None):
        """
        Record a single measurement for this histogram metric.

        Args:
            value: Single measured value for histogram distribution
            additional_labels: Additional labels for this specific measurement
        """
        labels_key = self._labels_to_key(additional_labels)
        record_data = self._get_or_new_record_data(labels_key, additional_labels)

        # Update bucket counts and statistics
        self._insert_value_to_buckets(value, record_data)

    def record_multi(self, values: List[float], additional_labels: Optional[Dict[str, str]] = None):
        """
        Record multiple measurements for this histogram metric.

        Args:
            values: List of measured values for histogram distribution
            additional_labels: Additional labels for this specific measurement
        """
        labels_key = self._labels_to_key(additional_labels)
        record_data = self._get_or_new_record_data(labels_key, additional_labels)

        # Update bucket counts and statistics for all values
        for value in values:
            self._insert_value_to_buckets(value, record_data)

    def record_bucket_counts(self, counts: List[float], additional_labels: Optional[Dict[str, str]] = None):
        """
        Record a list of measurements for this histogram metric.
        This function only updates bucket counts and total count, not sum/min/max.

        Args:
            values: List of measured values for histogram distribution
            additional_labels: Additional labels for this specific measurement
        """
        labels_key = self._labels_to_key(additional_labels)
        record_data = self._get_or_new_record_data(labels_key, additional_labels or {})

        for i, count in enumerate(counts):
            record_data.bucket_counts[i] += count
            record_data.total_count += count

    def _get_or_new_record_data(self, labels_key: str, labels: Dict[str, str]) -> HistogramRecordData:
        # For histogram, we accumulate values rather than overwriting
        if labels_key in self._data:
            record_data = self._data[labels_key].data
        else:
            # Create new histogram record data
            record_data = HistogramRecordData(
                bucket_counts=[0] * (len(self.buckets) + 1),
                total_count=0,
                sum=None,
                min=None,
                max=None,
            )

            # Store with labels
            self._data[labels_key] = MetricDataEntry(data=record_data, labels=labels)

        return record_data

    def _insert_value_to_buckets(self, value: float, record_data: HistogramRecordData):
        """
        Update bucket count for a single value.

        Args:
            value: The value to categorize into buckets
            record_data: The histogram record data to update
        """
        for i, bucket_boundary in enumerate(self.buckets):
            if value <= bucket_boundary:
                record_data.bucket_counts[i] += 1
                break
        else:
            # Value is greater than all bucket boundaries, add to overflow bucket
            record_data.bucket_counts[-1] += 1

        record_data.total_count += 1

        if record_data.sum is None:
            record_data.sum = value
        else:
            record_data.sum += value

        if record_data.min is None or value < record_data.min:
            record_data.min = value

        if record_data.max is None or value > record_data.max:
            record_data.max = value
