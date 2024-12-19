"""
This file defines the classes accepting metrics and records from snappi tests.
IMPORTANT: Please use the standard labels:
testbed.id, os.version, testcase, testrun.id, device.id, psu.id, port.id, sensor.id
"""

import logging
import json
import datetime
import time

from typing import List, Dict, Union
from metrics_reporter import MetricReporterFactory, MetricsReporter

class Metric:
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 reporter: MetricReporterFactory):
        """
        Args:
            name (str): metric name (e.g., psu power, sensor temperature, port stats, etc.)
            description (str): brief description of the metric
            unit (str): metric unit (e.g., seconds, bytes)
            reporter (MetricReporterFactory): object of MetricReporterFactory
        """
        self.name = name
        self.description = description
        self.unit = unit
        self.reporter = reporter

    def __repr__(self):
        return (f"Metric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter={self.reporter!r})")


class GaugeMetric(Metric):
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 reporter: MetricReporterFactory):
        # Initialize the base class
        super().__init__(name, description, unit, reporter)

    def set_gauge_metric(self, scope_labels: Dict[str, str], value: Union[int, str, float]):
        # Add scope level labels and set the metric value
        gauge_metric = {
            "name": self.name,
            "description": self.description,
            "unit": self.unit,
            **scope_labels,  # Add scope_labels to the dictionary
            "value": value   # Add the metric value
        }
        self.reporter.update_metrics(gauge_metric)

    def __repr__(self):
        return (f"GaugeMetric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter={self.reporter!r})")
