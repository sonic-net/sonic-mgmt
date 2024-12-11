# This file defines the classes exporting metrics and records to database.
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

    def create_metrics_reporter(self, data_type: str = "metrics"):
        """
        Creates a specific metrics reporter based on the provided type.

        Args:
            type (str): The type of metrics reporter to create. Default is 'otel'.

        Returns:
            An instance of the specified metrics reporter.
        """
        if data_type == "metrics":
            self.reporter = OtelMetricReporter(self.connection)
            return self.reporter
        elif data_type == "records":
            return KustoReporter(self.connection)
        else:
            raise ValueError(f"Unsupported reporter type: {data_type}")
    def create_metrics_reporter(self):


class OtelMetricReporter:
    def __init__(self, connection):
        # Temporary code initializing the OtelMetricReporter
        # will be replaced with OpenTelemetry connection
        self.connection = connection
        self.metrics = []

    def register_metrics(self, metrics):
        self.metrics.append(metrics)

    @abstractmethod
    def report(self, timestamp):
        """
        Abstract method to report metrics at a given timestamp.
        Subclasses must override this method.
        """
        pass


class KustoReporter:
    def __init__(self, connection):
        # Temporary code initializing the KustoReporter
        # will be replaced with Kusto connection
        self.connection = connection
        self.records = []

    def register_records(self, records):
        self.records.append(records)

    @abstractmethod
    def report(self, timestamp):
        """
        Abstract method to report records at a given timestamp.
        Subclasses must override this method.
        """
        pass

