"""
TimeSeries (TS) Reporter for real-time monitoring via OTLP.

This reporter sends metrics directly to OpenTelemetry collectors using
the OTLP protocol for real-time monitoring, dashboards, and alerting.
"""

import logging
import os
from typing import Dict, Optional, List
from ..base import Reporter, MetricRecord
from ..constants import (
    REPORTER_TYPE_TS, METRIC_TYPE_GAUGE, METRIC_TYPE_HISTOGRAM,
    ENV_SONIC_MGMT_TS_REPORT_ENDPOINT
)

# OTLP exporter imports (optional - graceful degradation if not available)
try:
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.sdk.metrics.export import (
        MetricsData, ResourceMetrics, ScopeMetrics, Metric,
        Gauge, Histogram, AggregationTemporality
    )
    from opentelemetry.sdk.metrics._internal.point import (
        NumberDataPoint, HistogramDataPoint
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.util.instrumentation import InstrumentationScope
    OTLP_AVAILABLE = True
except ImportError as e:
    OTLP_AVAILABLE = False
    logging.warning(f"OTLP exporter not available, TSReporter will operate in mock mode: {e}")


class TSReporter(Reporter):
    """
    TimeSeries reporter for real-time monitoring via OTLP.

    Sends metrics directly to OpenTelemetry collectors using the OTLP protocol
    without requiring the full OpenTelemetry SDK setup.
    """

    def __init__(self, endpoint: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                 request=None, tbinfo=None):
        """
        Initialize TS reporter with OTLP exporter.

        Args:
            endpoint: OTLP collector endpoint (default: from SONIC_MGMT_TS_REPORT_ENDPOINT env var)
            headers: Additional headers for OTLP requests
            request: pytest request object for test context
            tbinfo: testbed info fixture data
        """
        super().__init__(REPORTER_TYPE_TS, request, tbinfo)

        # Configuration
        self.endpoint = endpoint or os.environ.get(ENV_SONIC_MGMT_TS_REPORT_ENDPOINT, 'http://localhost:4317')
        self.headers = headers or {}
        self.mock_exporter = None  # For testing compatibility
        self._setup_exporter()

    def _setup_exporter(self):
        """
        Set up OTLP metric exporter.
        """
        if not OTLP_AVAILABLE:
            self.exporter = None
            return

        try:
            self.exporter = OTLPMetricExporter(
                endpoint=self.endpoint,
                headers=self.headers
            )
            logging.info(f"TSReporter: OTLP exporter initialized for endpoint {self.endpoint}")
        except Exception as e:
            logging.error(f"TSReporter: Failed to initialize OTLP exporter: {e}")
            self.exporter = None

    def set_mock_exporter(self, mock_exporter_func):
        """
        Set a mock exporter function for testing.

        Args:
            mock_exporter_func: Function that takes MetricsData as parameter.
                              Set to None to clear mock exporter.
        """
        self.mock_exporter = mock_exporter_func
        logging.info(f"TSReporter: Mock exporter {'set' if mock_exporter_func else 'cleared'}")

    def _report(self, timestamp: float):
        """
        Report all collected metrics via OTLP.

        Args:
            timestamp: Timestamp for this reporting batch (automatically in nanoseconds)
        """
        logging.info(f"TSReporter: Reporting {len(self.recorded_metrics)} measurements (OTLP: {OTLP_AVAILABLE})")

        if not OTLP_AVAILABLE:
            self._report_metrics_as_log(timestamp)
            return

        # Create MetricsData using SDK objects
        metrics_data = self._create_metrics_data(timestamp)
        if not metrics_data:
            return

        if self.mock_exporter:
            self.mock_exporter(metrics_data)
        else:
            self._export_metrics(metrics_data)

    def _create_metrics_data(self, timestamp: float) -> Optional[MetricsData]:
        """
        Create MetricsData using SDK objects from current measurements.

        Args:
            timestamp: Timestamp for all measurements in this batch

        Returns:
            MetricsData object or None if creation fails
        """
        if not OTLP_AVAILABLE:
            return None

        # Create SDK Resource
        resource = self._create_resource()

        # Group measurements by metric for efficient batching
        metric_groups = {}
        for record in self.recorded_metrics:
            key = (record.metric.name, record.metric.metric_type)
            if key not in metric_groups:
                metric_groups[key] = {
                    'metric': record.metric,
                    'records': []
                }
            metric_groups[key]['records'].append(record)

        # Create SDK metrics
        sdk_metrics = []
        for (metric_name, metric_type), group in metric_groups.items():
            sdk_metric = self._create_sdk_metric(group['metric'], group['records'], timestamp)
            if sdk_metric:
                sdk_metrics.append(sdk_metric)

        if len(sdk_metrics) == 0:
            return None

        # Create ResourceMetrics with ScopeMetrics
        scope = InstrumentationScope(
            name="sonic-test-telemetry",
            version="1.0.0"
        )

        scope_metrics = ScopeMetrics(
            scope=scope,
            metrics=sdk_metrics,
            schema_url=""
        )

        resource_metrics = ResourceMetrics(
            resource=resource,
            scope_metrics=[scope_metrics],
            schema_url=""
        )

        return MetricsData(resource_metrics=[resource_metrics])

    def _create_resource(self) -> Resource:
        """
        Create SDK Resource with attributes.
        """
        # Merge test context with resource attributes
        all_attrs = {
            "service.name": "sonic-test-telemetry",
            "service.version": "1.0.0",
            **self.test_context,
        }

        return Resource.create(all_attrs)

    def _create_sdk_metric(self, metric, records: List[MetricRecord],
                           timestamp: float) -> Optional[Metric]:
        """
        Create SDK Metric from metric records.

        Args:
            metric: Metric instance from telemetry framework
            records: List of MetricRecord objects
            timestamp: Timestamp for all measurements

        Returns:
            SDK Metric or None if conversion fails
        """
        timestamp_ns = int(timestamp)

        if metric.metric_type == METRIC_TYPE_GAUGE:
            data_points = []
            for record in records:
                data_point = NumberDataPoint(
                    attributes=record.labels,
                    start_time_unix_nano=timestamp_ns,
                    time_unix_nano=timestamp_ns,
                    value=float(record.data)
                )
                data_points.append(data_point)

            gauge_data = Gauge(data_points=data_points)
            return Metric(
                name=metric.name,
                description=metric.description,
                unit=metric.unit,
                data=gauge_data
            )

        elif metric.metric_type == METRIC_TYPE_HISTOGRAM:
            data_points = []
            for record in records:
                histogram_data = record.data
                data_point = HistogramDataPoint(
                    attributes=record.labels,
                    start_time_unix_nano=timestamp_ns,
                    time_unix_nano=timestamp_ns,
                    count=histogram_data.total_count,
                    sum=histogram_data.sum,
                    bucket_counts=histogram_data.bucket_counts,
                    explicit_bounds=metric.buckets,
                    min=histogram_data.min,
                    max=histogram_data.max,
                )
                data_points.append(data_point)

            histogram_data = Histogram(
                data_points=data_points,
                aggregation_temporality=AggregationTemporality.CUMULATIVE
            )
            return Metric(
                name=metric.name,
                description=metric.description,
                unit=metric.unit,
                data=histogram_data
            )

        else:
            return None

    def _export_metrics(self, metrics_data: MetricsData):
        """
        Export MetricsData using the configured OTLP exporter.

        Args:
            metrics_data: MetricsData object to export
        """
        if self.exporter:
            result = self.exporter.export(metrics_data)
            if result.name == 'SUCCESS':
                logging.info("TSReporter: Successfully exported to OTLP endpoint")
            else:
                logging.warning(f"TSReporter: Export failed with result: {result}")
        else:
            logging.warning("TSReporter: No exporter available")

    def _report_metrics_as_log(self, timestamp: float):
        """
        Report metrics as log entries.

        Args:
            timestamp: Timestamp for this reporting batch
        """
        for record in self.recorded_metrics:
            logging.info(f"TSReporter: {record.metric.name}={record.data} "
                         f"labels={record.labels} timestamp={timestamp}")
