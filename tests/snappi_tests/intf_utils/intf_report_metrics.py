import logging
import json
import datetime
import time

from typing import List, Dict, Union
from intf_accept_metrics import Metric GaugeMetric

class MetricReporterFactory:
    def __init__(self, connection):
        # Temporary code initializing the MetricReporterFactory with a database connection
        # will be replaced with OpenTelemetry connection
        self.connection = connection
        self.reporter = None

    def create_metrics_reporter(self):
        self.reporter = OtelMetricReporter(self.connection)
        return self.reporter

class OtelMetricReporter:
    def __init__(self, connection):
        # Temporary code initializing the OtelMetricReporter
        # will be replaced with OpenTelemetry connection
        self.connection = connection
        self.metrics = []

    def register_metric(self, metrics):
        self.metrics.append(metrics)

    def report(self, timestamp):
        # Temporary code to report metrics
        print(f"Reporting metrics at {timestamp}")
        for metric in self.metrics:
            print(metric)


