# This file defines the classes reporting metrics and records to the corresponding database.

import logging
import json
import datetime
import time
from pprint import pprint
from typing import List, Dict, Union

#from metrics_accepter import Metric, GaugeMetric

class MetricReporterFactory:
    def __init__(self):
        self.reporter = None

    def create_metrics_reporter(self, resource_labels: Dict[str, str]):
        self.reporter = MetricsReporter(resource_labels)
        return self.reporter

    def create_records_reporter(self, resource_labels: Dict[str, str]):
        self.reporter = RecordsReporter(resource_labels)
        return self.reporter


class MetricsReporter:
    def __init__(self, resource_labels: Dict[str, str]):
        # Temporary code initializing a MetricsReporter
        # will be replaced with a real initializer such as OpenTelemetry 
        self.resource_labels = resource_labels
        self.timestamp = int(time.time() * 1_000_000_000) # epoch time in nanoseconds
        self.metrics = []

    def update_metrics(self, gauge_metric: Dict[str, Union[int, str, float]]):
        # add a new metric
        self.metrics.append(gauge_metric)

    def report(self):
        """
        Abstract method to report metrics at a given timestamp.
        Subclasses must override this method.
        pprint(self.metrics)
        """
        pass


class RecordsReporter:
    def __init__(self, resource_labels: Dict[str, str]):
        # Temporary code initializing a RecordsReporter
        # will be replaced with a real initializer such as Kusto
        self.resource_labels = resource_labels
        self.timestamp = int(time.time() * 1_000_000_000) # epoch time in nanoseconds
        self.records = []

    def report(self):
        """
        Abstract method to report records at a given timestamp.
        Subclasses must override this method.
        """
        pass

