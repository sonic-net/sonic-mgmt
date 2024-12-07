# This file defines the interfaces that snappi tests accept external metrics.
import logging
import json
import datetime
import time

from typing import List, Dict, Union
from intf_report_metrics import MetricReporterFactory OtelMetricReporter

class Metric:
    def __init__(self,
                 name,
                 description,
                 unit,
                 timestamp,
                 testbed_name,
                 os_version,
                 testcase_name,
                 test_run_id,
                 device_id,
                 component_id,
                 reporter: MetricReporterFactory,
                 metadata = None):
        """
        Args:
            name (str): metric name (e.g., psu power, sensor temperature, port stats, etc.)
            description (str): brief description of the metric
            unit (str): metric unit (e.g., seconds, bytes)
            timestamp (int): UNIX Epoch time in nanosecond, when the metric is collected
            testbed_name (str): testbed name
            os_version (str): switch OS version
            testcase_name (str): test case name
            test_run_id (str): ID of the test run
            device_id (str): switch device ID
            component_id (str): ID of the component (e.g., psu, sensor, port, etc.)
            reporter(obj): object of MetricReporterFactory
            metadata (str): e.g. serial number, model number, etc. Default to an empty dictionary if None
        Returns:
            N/A
        """
        self.name          = name
        self.description   = description
        self.unit          = unit
        self.timestamp     = timestamp
        self.testbed_name  = testbed_name
        self.os_version    = os_version
        self.testcase_name = testcase_name
        self.test_run_id   = test_run_id
        self.device_id     = device_id
        self.component_id  = component_id
        self.reporter      = reporter.create_metrics_reporter()
        self.metadata      = metadata or {}

    def __repr__(self):
        return (f"Metric(name={self.name!r}, description={self.description!r}, "
                f"unit={self.unit!r}, timestamp={self.timestamp!r}, "
                f"testbed_name={self.testbed_name!r}, os_version={self.os_version!r}, "
                f"testcase_name={self.testcase_name!r}, test_run_id={self.test_run_id!r}, "
                f"device_id={self.device_id!r}, component_id={self.component_id!r}, "
                f"reporter={self.reporter!r}), metadata={self.metadata!r})")


class GaugeMetric(Metric):
    def __init__(self,
             name,
             description,
             unit,
             timestamp,
             testbed_name,
             os_version,
             testcase_name,
             test_run_id,
             device_id,
             component_id,
             reporter: MetricReporterFactory,
             metadata = None,
             metrics: Dict[str, Union[int, str, float]] = None):
        # Initialize the base class
        super().__init__(name, description, unit, timestamp, testbed_name, os_version,
                         testcase_name, test_run_id, device_id, component_id, reporter, metadata, metrics)

        # Additional fields for GaugeMetric
        self.metrics = metrics or {}

    def add_metrics(self, new_metrics: Dict[str, Union[int, str, float]]):
        # Add new elements to the metrics dictionary.
        # new_metrics: Dictionary containing new key-value pairs to append.
        self.metrics.update(new_metrics)

    def __repr__(self):
        return (f"ExtendedMetric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"timestamp={self.timestamp!r}, "
                f"testbed_name={self.testbed_name!r}, "
                f"os_version={self.os_version!r}, "
                f"testcase_name={self.testcase_name!r}, "
                f"test_run_id={self.test_run_id!r}, "
                f"device_id={self.device_id!r}, "
                f"component_id={self.component_id!r}, "
                f"component_id={self.reporter!r}, "
                f"metadata={self.metadata!r}, "
                f"metrics={self.metrics!r})")
