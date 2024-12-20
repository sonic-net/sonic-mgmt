"""
This file defines the classes receiving metrics and test results from snappi tests.
"""

import logging
import json
import datetime
import time

from pprint import pprint
from typing import List, Dict, Union

# Function to load allowed labels from a JSON file
def load_allowed_labels(filename="allowed_labels.json"):
    with open(filename, "r") as f:
        data = json.load(f)
        # print(data)
    return set(data["allowed_labels"])
allowed_labels = load_allowed_labels()

class MetricsReporter:
    def __init__(self, resource_labels: Dict[str, str]):
        for label in resource_labels:
            if label not in allowed_labels:
                raise LabelError(f"Invalid label: {label}.")

        # Temporary code initializing a MetricsReporter
        # will be replaced with a real initializer such as OpenTelemetry 
        self.resource_labels = resource_labels
        self.metrics = []

    def stash_metric(self, new_metric: 'GaugeMetric', labels: Dict[str, str], value: Union[int, str, float]):
        # add a new metric
        self.metrics.append({"labels": labels, "value": value})

    def report(self, timestamp=None):
        """
        Abstract method to report metrics at a given timestamp.
        Subclasses must override this method.
        The input timestamp must be UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970
        pass
        """
        if timestamp is not None:
            current_time = timestamp
        else:
            current_time = time.time_ns()

        # save the metrics in a local variable and release the metrics in the object
        stashed_metrics = self.metrics
        self.metrics = []

        """
        print(f"Current time (ns): {current_time}")
        pprint(self.resource_labels)
        pprint(stashed_metrics)
        process_stashed_metrics(current_time, stashed_metrics)
        """


class TestResultsReporter:
    def __init__(self, resource_labels: Dict[str, str]):
        for label in resource_labels:
            if label not in allowed_labels:
                raise LabelError(f"Invalid label: {label}.")

        # Temporary code initializing a TestResultsReporter
        # will be replaced with a real initializer such as Kusto
        self.resource_labels = resource_labels
        self.test_results = []

    def stash_test_results(self, labels: Dict[str, str], value: Union[int, str, float]):
        # add a new test result
        self.test_results.append({"labels": labels, "value": value})

    def report(self, timestamp=None):
        """
        Abstract method to report test results at a given timestamp.
        Subclasses must override this method.
        The input timestamp must be UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970
        """
        if timestamp is not None:
            current_time = timestamp
        else:
            current_time = time.time_ns()

        # save the test results in a local variable and release the test results in the object
        stashed_test_results = self.test_results
        self.test_results = []

        """
        print(f"Current time (ns): {current_time}")
        pprint(self.resource_labels)
        pprint(self.test_results)
        process_stashed_test_results(current_time, stashed_test_results)
        """


class Metric:
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 reporter: MetricsReporter):
        """
        Args:
            name (str): metric name (e.g., psu power, sensor temperature, port stats, etc.)
            description (str): brief description of the metric
            unit (str): metric unit (e.g., seconds, bytes)
            reporter (MetricsReporter): object of MetricsReporter
        """
        self.name = name
        self.description = description
        self.unit = unit
        self.reporter = reporter

    def __repr__(self):
        return (f"Metric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter=repr(self.reporter))")


class GaugeMetric(Metric):
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 reporter: MetricsReporter):
        # Initialize the base class
        super().__init__(name, description, unit, reporter)

    def record(self, scope_labels: Dict[str, str], value: Union[int, str, float]):
        for label in scope_labels:
            if label not in allowed_labels:
                raise LabelError(f"Invalid label: {label}.")

        # Save the metric into the reporter
        self.reporter.stash_metric(self, scope_labels, value)

    def __repr__(self):
        return (f"GaugeMetric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter=repr(self.reporter))")
