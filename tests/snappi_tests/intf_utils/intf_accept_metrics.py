# This file defines the interfaces that snappi tests accept external metrics.

import logging
import json
import datetime
import time

from typing import List, Dict, Union
from intf_report_metrics import MetricReporterFactory OtelMetricReporter

class Metric:
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 timestamp: int,
                 device_id: str,
                 component_id: str,
                 reporter: MetricReporterFactory,
                 metadata: Dict[str, str]):
        """
        Args:
            name (str): metric name (e.g., psu power, sensor temperature, port stats, etc.)
            description (str): brief description of the metric
            unit (str): metric unit (e.g., seconds, bytes)
            timestamp (int): UNIX Epoch time in nanoseconds when the metric is collected
            device_id (str): switch device ID
            component_id (str): ID of the component (e.g., psu, sensor, port, etc.), where metrics are produced
            reporter (MetricReporterFactory): object of MetricReporterFactory
            metadata (Dict[str, str]): Additional information such as serial number, model number, testbed name, OS version, etc.
        """
        self.name = name
        self.description = description
        self.unit = unit
        self.timestamp = timestamp
        self.device_id = device_id
        self.component_id = component_id
        self.reporter = reporter.create_metrics_reporter()

        # Ensure mandatory fields are set in metadata
        self.metadata = metadata
        self.metadata.update({
            "testbed_name": metadata.get("testbed_name", ""),
            "os_version": metadata.get("os_version", ""),
            "testcase_name": metadata.get("testcase_name", ""),
            "test_run_id": metadata.get("test_run_id", "")
            "model_number": metadata.get("model_number", "")
            "serial_number": metadata.get("serial_number", "")
        })

    def __repr__(self):
        return (f"Metric(name={self.name!r}, description={self.description!r}, "
                f"unit={self.unit!r}, timestamp={self.timestamp!r}, "
                f"device_id={self.device_id!r}, component_id={self.component_id!r}, "
                f"reporter={self.reporter!r}, metadata={self.metadata!r})")


class GaugeMetric(Metric):
    def __init__(self,
                 name: str,
                 description: str,
                 unit: str,
                 timestamp: int,
                 device_id: str,
                 component_id: str,
                 reporter: MetricReporterFactory,
                 metadata: Dict[str, str],
                 metrics: Dict[str, Union[int, str, float]] = None):
        # Initialize the base class
        super().__init__(name, description, unit, timestamp, device_id, component_id, reporter, metadata, metrics)

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
                f"device_id={self.device_id!r}, "
                f"component_id={self.component_id!r}, "
                f"reporter={self.reporter!r}, "
                f"metadata={self.metadata!r}, "
                f"metrics={self.metrics!r})")
