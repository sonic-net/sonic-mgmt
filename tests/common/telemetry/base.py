"""
Base classes for the SONiC telemetry framework.

This module contains the abstract base classes and core interfaces
for the telemetry system including Reporter, Metric, and MetricCollection.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, List, Union, Callable
from dataclasses import dataclass
import os
import time
import re
from .constants import (
    METRIC_LABEL_TEST_TESTBED, METRIC_LABEL_TEST_OS_VERSION,
    METRIC_LABEL_TEST_TESTCASE, METRIC_LABEL_TEST_FILE,
    METRIC_LABEL_TEST_JOB_ID, METRIC_LABEL_TEST_PARAMS_PREFIX,
    ENV_SONIC_MGMT_TESTBED_NAME, ENV_SONIC_MGMT_BUILD_VERSION, ENV_SONIC_MGMT_JOB_ID
)


@dataclass
class HistogramRecordData:
    """
    Data class for storing histogram record data.

    This class holds the bucket counts and the total count for a histogram
    measurement, providing a structured way to manage histogram data.
    """
    bucket_counts: List[int]
    total_count: int
    sum: Optional[float] = None
    min: Optional[float] = None
    max: Optional[float] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "bucket_counts": self.bucket_counts,
            "total_count": self.total_count,
            "sum": self.sum,
            "min": self.min,
            "max": self.max
        }


# Type alias for metric data that can be either a single value or a list of values
MetricRecordDataT = Union[float, HistogramRecordData]


def default_value_convertor(raw_value: str) -> float:
    """
    Default conversion for metric values defined via MetricDefinition.

    Removes non-digit characters (except '.') to provide a more robust baseline convertor.
    This helps us handling values like "8,287,919,536", "9.39%" and etc.
    """
    if raw_value == "N/A":
        return -1
    if raw_value == "False":
        return 0
    if raw_value == "True":
        return 1

    numeric_value = re.sub(r"[^0-9.]", "", raw_value)
    if not numeric_value:
        raise ValueError(f"Cannot convert '{raw_value}' to float")

    return float(numeric_value)


@dataclass
class MetricDefinition:
    """
    Definition for a metric in a collection.

    This class provides a clean, type-safe way to define metrics
    with all their attributes in a structured format.
    """
    attribute_name: str
    metric_name: str
    description: str
    unit: str
    value_convertor: Callable[[str], float] = default_value_convertor

    def __str__(self) -> str:
        """Return a readable string representation."""
        return f"MetricDefinition({self.attribute_name}: {self.metric_name})"


@dataclass
class MetricDataEntry:
    """
    Internal storage entry for metric data with associated labels.

    This stores the metric data along with the labels that apply to it,
    avoiding the need to parse labels from keys.
    """
    data: MetricRecordDataT
    labels: Dict[str, str]


@dataclass
class MetricRecord:
    """
    Record of a metric measurement.

    This replaces the tuple-based measurement storage with a type-safe
    dataclass that provides better code clarity and maintainability.
    """
    metric: 'Metric'
    data: MetricRecordDataT
    labels: Dict[str, str]

    def __str__(self) -> str:
        """Return a readable string representation."""
        value_str = f"[{len(self.data)} values]" if isinstance(self.data, list) else str(self.data)
        return f"MetricRecord({self.metric.name}={value_str}, labels={len(self.labels)})"


class Reporter(ABC):
    """
    Abstract base class for telemetry reporters.

    Reporters are responsible for collecting and dispatching metrics
    to their respective backends (OpenTelemetry for TS, files for DB).
    """

    def __init__(self, reporter_type: str, request=None, tbinfo=None):
        """
        Initialize reporter with type identifier.

        Args:
            reporter_type: Type of reporter ('ts' or 'db')
            request: pytest request object for test context
            tbinfo: testbed info fixture data
        """
        self.reporter_type = reporter_type
        self.test_context = self._detect_test_context(request, tbinfo)
        self.registered_metrics: List['Metric'] = []
        self._gathered_metrics: List[MetricRecord] = []

    def _detect_test_context(self, request=None, tbinfo=None) -> Dict[str, str]:
        """
        Automatically detect test context from pytest data and tbinfo fixture.

        Args:
            request: pytest request object for test context
            tbinfo: testbed info fixture data

        Returns:
            Dict containing test metadata labels
        """
        context = {}

        # Get test case name from pytest request
        context[METRIC_LABEL_TEST_TESTCASE] = request.node.name
        context[METRIC_LABEL_TEST_FILE] = os.path.basename(request.node.fspath.strpath)

        # Get test parameters if available
        if hasattr(request.node, 'callspec') and request.node.callspec:
            for param_name, param_value in request.node.callspec.params.items():
                context[f'{METRIC_LABEL_TEST_PARAMS_PREFIX}.{param_name}'] = str(param_value)

        if tbinfo is not None:
            # Get testbed name from tbinfo fixture
            context[METRIC_LABEL_TEST_TESTBED] = tbinfo.get('conf-name', 'unknown') if tbinfo else 'unknown'

        # Fallback to environment variables if pytest data not available
        if not context.get(METRIC_LABEL_TEST_TESTBED):
            context[METRIC_LABEL_TEST_TESTBED] = os.environ.get(ENV_SONIC_MGMT_TESTBED_NAME, 'unknown')

        context[METRIC_LABEL_TEST_OS_VERSION] = os.environ.get(ENV_SONIC_MGMT_BUILD_VERSION, 'unknown')
        context[METRIC_LABEL_TEST_JOB_ID] = os.environ.get(ENV_SONIC_MGMT_JOB_ID, 'unknown')

        return context

    def register_metric(self, metric: 'Metric'):
        """
        Register a metric with this reporter.

        Args:
            metric: Metric instance to register
        """
        if metric not in self.registered_metrics:
            self.registered_metrics.append(metric)

    def gather_all_recorded_metrics(self):
        """
        Gather all recorded metrics from registered metrics and store them in the reporter.

        This method collects all metrics from individual metric objects and stores them
        centrally in the reporter for efficient access.
        """
        self._gathered_metrics.clear()
        for metric in self.registered_metrics:
            records = metric.get_metric_records()
            self._gathered_metrics.extend(records)

    @property
    def recorded_metrics(self) -> List[MetricRecord]:
        """Get the gathered recorded metrics from the reporter's central storage."""
        return self._gathered_metrics

    def recorded_metrics_count(self) -> int:
        """
        Get the number of pending measurements.

        Returns:
            Count of measurements in the gathered metrics storage
        """
        return len(self._gathered_metrics)

    def report(self, timestamp: float = None):
        """
        Report all collected metrics to the backend and clear the buffers.

        This method gathers all metrics, generates the timestamp and calls the subclass-specific _report method.

        Args:
            timestamp: Optional timestamp in nanoseconds. If not provided, uses current time.
        """
        # Gather all metrics from registered metrics first
        self.gather_all_recorded_metrics()

        if len(self._gathered_metrics) == 0:
            return

        if timestamp is None:
            timestamp = time.time_ns()
        self._report(timestamp)

        # Clear data from all registered metrics and gathered storage
        for metric in self.registered_metrics:
            metric.clear_data()
        self._gathered_metrics.clear()

    @abstractmethod
    def _report(self, timestamp: float):
        """
        Implementation-specific reporting logic.

        Args:
            timestamp: Timestamp for this reporting batch
        """
        pass


class Metric(ABC):
    """
    Abstract base class for telemetry metrics.

    Metrics represent measurable quantities following OpenTelemetry conventions.
    """

    def __init__(self, metric_type: str, name: str, description: str, unit: str, reporter: Reporter,
                 value_convertor: Callable[[str], MetricRecordDataT] = None,
                 common_labels: Optional[Dict[str, str]] = None):
        """
        Initialize metric with metadata.

        Args:
            name: Metric name in OpenTelemetry format (lowercase.snake_case.dot_separated)
            description: Human-readable description
            unit: Unit of measurement
            reporter: Reporter instance to send measurements to
            common_labels: Common labels to apply to all measurements of this metric
        """
        self.metric_type = metric_type
        self.name = name
        self.description = description
        self.unit = unit
        self.reporter = reporter
        self._value_convertor = value_convertor
        self._common_labels = common_labels or {}
        self._data: Dict[str, MetricDataEntry] = {}  # Map of labels_key -> MetricDataEntry

        # Register this metric with the reporter
        self.reporter.register_metric(self)

    @property
    def labels(self) -> Dict[str, str]:
        """
        Get the common labels for this metric (read-only).

        Returns:
            Dictionary containing common labels for this metric
        """
        return self._common_labels

    def _labels_to_key(self, labels: Optional[Dict[str, str]]) -> str:
        """
        Convert labels dictionary to a string key for data storage.

        Args:
            labels: Labels dictionary

        Returns:
            String key representing the labels
        """
        if labels is None:
            return ""

        # Sort labels for consistent key generation
        sorted_items = sorted(labels.items())
        return '|'.join(f"{k}={v}" for k, v in sorted_items)

    def get_metric_records(self) -> List[MetricRecord]:
        """
        Get all metric records from stored data.

        Args:
            test_context: Test context from reporter (unused, kept for compatibility)

        Returns:
            List of MetricRecord objects
        """
        records = []
        for _, entry in self._data.items():
            merged_labels = {**self._common_labels, **entry.labels}
            record = MetricRecord(metric=self, data=entry.data, labels=merged_labels)
            records.append(record)
        return records

    def clear_data(self):
        """Clear all stored data from this metric."""
        self._data.clear()


class MetricCollection:
    """
    Base class for organizing related metrics into collections.

    This provides a convenient way to group metrics that are commonly
    used together (e.g., port metrics, PSU metrics).

    Subclasses should define METRICS_DEFINITIONS as a class attribute
    containing MetricDefinition entries describing the attribute, metric name,
    description, unit, and optional value convertor.
    """

    # Subclasses should override this with their metric definitions
    METRICS_DEFINITIONS: List[MetricDefinition] = []

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        """
        Initialize metric collection.

        Args:
            reporter: Reporter instance for all metrics in this collection
            labels: Common labels to apply to all metrics in this collection
        """
        self.reporter = reporter
        self.labels = labels or {}
        self._create_metrics()

    def _create_metrics(self):
        """
        Create all metrics using the METRICS_DEFINITIONS class attribute.

        Uses the GaugeMetric class by default. Subclasses can override this method
        if they need to use different metric types.
        """
        # Import here to avoid circular imports
        from .metrics.gauge import GaugeMetric

        for definition in self.METRICS_DEFINITIONS:
            metric = GaugeMetric(
                name=definition.metric_name,
                description=definition.description,
                unit=definition.unit,
                reporter=self.reporter,
                common_labels=self.labels
            )
            setattr(self, definition.attribute_name, metric)
