"""
This file defines the classes receiving metrics from snappi tests and processing them.
"""
import time

from copy import deepcopy
from typing import Dict, Union


class PeriodicMetricsReporter:
    def __init__(self, common_labels: Dict[str, str]):
        # Will be replaced with a real initializer such as OpenTelemetry
        self.common_labels = deepcopy(common_labels)
        self.metrics = []

    def stash_record(self, new_metric: 'Metric', labels: Dict[str, str], name: str, value: Union[int, float]):
        # add a new periodic metric
        copied_labels = deepcopy(labels)
        self.metrics.append({"labels": copied_labels, "name": name, "value": value})

    def report(self, timestamp=time.time_ns()):
        """
        Report metrics at a given timestamp.
        The input timestamp must be UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970

        # save the metrics in a local variable and release the metrics in the object
        stashed_metrics = self.metrics
        self.metrics = []

        """
        pass


class FinalMetricsReporter:
    def __init__(self, common_labels: Dict[str, str]):
        # Will be replaced with a real initializer such as Kusto
        self.common_labels = deepcopy(common_labels)
        self.metrics = []

    def stash_record(self, new_metric: 'Metric', labels: Dict[str, str], name: str, value: Union[int, float]):
        # add a new final metric
        copied_labels = deepcopy(labels)
        self.metrics.append({"labels": copied_labels, "name": name, "value": value})

    def report(self, timestamp=time.time_ns()):
        """
        Report metrics at a given timestamp.
        The input timestamp must be UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970

        # save the metrics in a local variable and release the metrics in the object
        stashed_metrics = self.metrics
        self.metrics = []

        """
        pass


class Metric:
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 reporter: PeriodicMetricsReporter):
        """
        Args:
            name (str): metric name (e.g., psu power, sensor temperature, port stats, etc.)
            description (str): brief description of the metric
            unit (str): metric unit (e.g., seconds, bytes)
            reporter (PeriodicMetricsReporter): object of PeriodicMetricsReporter
        """
        self.name = name
        self.description = description
        self.unit = unit
        self.reporter = reporter

    def __repr__(self):
        return (f"Metric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter={self.reporter})")


class GaugeMetric(Metric):
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 reporter: PeriodicMetricsReporter):
        # Initialize the base class
        super().__init__(name, description, unit, reporter)

    def record(self, metric_labels: Dict[str, str], value: Union[int, float]):
        # Save the metric into the reporter
        self.reporter.stash_record(self, metric_labels, self.name, value)

    def __repr__(self):
        return (f"GaugeMetric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter={self.reporter})")
