"""
This file defines the classes receiving metrics from snappi tests and processing them.
"""
import time

from copy import deepcopy
from typing import Dict, Final, Union

# Only certain labels are allowed
METRIC_LABEL_TESTBED: Final[str] = "test.testbed"                   # testbed name/ID
METRIC_LABEL_TEST_BUILD: Final[str] = "test.os.version"             # Software/build version
METRIC_LABEL_TEST_CASE: Final[str] = "test.testcase"                # test case name/ID
METRIC_LABEL_TEST_FILE: Final[str] = "test.file"                    # test file name
METRIC_LABEL_TEST_JOBID: Final[str] = "test.job.id"                 # test job ID
METRIC_LABEL_DEVICE_ID: Final[str] = "device.id"                    # device refers to the level of switch
METRIC_LABEL_DEVICE_PORT_ID: Final[str] = "device.port.id"
METRIC_LABEL_DEVICE_PSU_ID: Final[str] = "device.psu.id"
METRIC_LABEL_DEVICE_PSU_MODEL: Final[str] = "device.psu.model"
METRIC_LABEL_DEVICE_PSU_SERIAL: Final[str] = "device.psu.serial"
METRIC_LABEL_DEVICE_PSU_HW_REV: Final[str] = "device.psu.hw_rev"    # hardware revision
METRIC_LABEL_DEVICE_QUEUE_ID: Final[str] = "device.queue.id"
METRIC_LABEL_DEVICE_QUEUE_CAST: Final[str] = "device.queue.cast"    # unicast or multicast
METRIC_LABEL_DEVICE_SENSOR_ID: Final[str] = "device.sensor.id"
METRIC_LABEL_DEVICE_PG_ID: Final[str] = "device.pg.id"              # priority group
METRIC_LABEL_DEVICE_BUFFER_POOL_ID: Final[str] = "device.buffer_pool.id"


class PeriodicMetricsReporter:
    def __init__(self, common_labels: Dict[str, str]):
        # Will be replaced with a real initializer such as OpenTelemetry
        self.common_labels = deepcopy(common_labels)
        self.metrics = []

    def stash_record(self, new_metric: 'Metric', labels: Dict[str, str], value: Union[int, float]):
        # add a new periodic metric
        copied_labels = deepcopy(labels)
        self.metrics.append({"labels": copied_labels, "value": value})

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

    def stash_record(self, new_metric: 'Metric', labels: Dict[str, str], value: Union[int, float]):
        # add a new final metric
        copied_labels = deepcopy(labels)
        self.metrics.append({"labels": copied_labels, "value": value})

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
        self.reporter.stash_record(self, metric_labels, value)

    def __repr__(self):
        return (f"GaugeMetric(name={self.name!r}, "
                f"description={self.description!r}, "
                f"unit={self.unit!r}, "
                f"reporter={self.reporter})")
