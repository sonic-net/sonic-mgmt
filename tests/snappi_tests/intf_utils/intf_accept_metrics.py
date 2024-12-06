# This file defines the interfaces that snappi tests accept external metrics.

#  Metrics data are organized into the hierarchies below
#  TestMetrics
#    ├── TestID
#    └── DeviceMetrics
#       ├── DeviceID
#       └── Metric
#          ├── Name
#          ├── Description
#          ├── Unit
#          ├── metadata
#          └── data
#             └── Gauge
#
# A TestMetrics has its ID and a list of DeviceMetrics objects.
# A DeviceMetrics    has its ID and a list of Metric objects.
# A Metric has several attributes and data. So far we only have Gauge type data.
# A Gauge has a list of NumberDataPoint objects.
# A NumberDataPoint has its label, value, flags and the timestamp at which the data was collected.
#
#
#                           +-----------+
#                           |DataPoint 1|
#                           |  +-----+  |
#                           |  |label|  |
#               +-----+     |  +-----+  |
#               |  1  |---> |  +-----+  |
#               +-----+     |  |value|  |
#               |  .  |     |  +-----+  |
#               |  .  |     |  +-----+  |
#               |  .  |     |  |flags|  |
#               |  .  |     |  +-----+  |
#               |  .  |     +-----------+
#               |  .  |           .
#               |  .  |           .
#               |  .  |           .
#               |  .  |     +-----------+
#               |  .  |     |DataPoint M|
#               |  .  |     |  +-----+  | 
#               |  .  |     |  |label|  |
#               +-----+     |  +-----+  |
#               |  M  |---> |  +-----+  |
#               +-----+     |  |value|  |
#                           |  +-----+  |
#                           |  +-----+  |
#                           |  |flags|  |
#                           |  +-----+  |
#                           +-----------+




from typing import List, Dict, Union


############################## Accept Metrics ##############################

# All metrics of one TestMetrics object are from the same testbed runing the same
# software version. They are also from the same test case identified by test_run_id.
class TestMetrics:
    def __init__(self, testbed_name, os_version, testcase_name, test_run_id):
        self.testbed_name  = testbed_name
        self.os_version    = os_version
        self.testcase_name = testcase_name
        self.test_run_id   = test_run_id
        self.device_metrics = []

    def add_device_metrics(self, device_metric):
        self.device_metrics.append(device_metric)

    def __repr__(self):
        return f"TestMetrics(test={self.test}, device_metrics={self.device_metrics})"


# All metrics of one DeviceMetrics object are from the same device identified by device_id.
class DeviceMetrics:
    def __init__(self, device_id):
        self.device_id = device_id
        self.metrics   = []

    def add_metric(self, metric):
        self.metrics.append(metric)

    def __repr__(self):
        return f"DeviceMetrics(device={self.device}, metrics={self.metrics})"


# All metrics of one Metric object belong to the same category tagged by metric name,
# e.g.,  psu info, temperature info, port counters
class Metric:
    def __init__(self, name, description, unit, data_points, metadata = None):
        self.name        = name             # Metric name (e.g., psu, temperature)
        self.description = description      # Metric description
        self.unit        = unit             # Metric unit (e.g., seconds, bytes)
        self.data        = data             # Can be Gauge only
        self.metadata    = metadata or {}   # e.g. port_id, psu_id, default to an empty dictionary if None

    def __repr__(self):
        return (f"Metric(name={self.name}, description={self.description}, "
                f"unit={self.unit}, data={self.data})")


class Gauge:
    def __init__(self, time_unix_nano: int):
        self.time_unix_nano = time_unix_nano # UNIX Epoch time in nanoseconds
        self.data_points = []                # List of NumberDataPoint objects

    def add_data_point(self, data_point):
        self.data_points.append(data_point)

    def __repr__(self):
        return f"Gauge(data_points={self.data_points})"


class NumberDataPoint:
    def __init__(self, label: List[Dict[str, str]], value: Union[int, float], flags: int = None):
        self.label = label  # The key of key-value pairs in dictionaries
        self.value = value  # Metric value (can be double or integer)
        self.flags = flags  # Optional flags

    def __repr__(self):
        return (f"NumberDataPoint(label={self.label}, "
                f"time_unix_nano={self.time_unix_nano}, value={self.value}, flags={self.flags})")

############################## Report Metrics ##############################

class MetricReporterFactory:
    def __init__(self, testbed_name, testcase_name, test_run_id):
        self.testbed_name  = testbed_name
        self.testcase_name = testcase_name
        self.test_run_id   = test_run_id

    def create_metrics_reporter(self):
        # Create MetricsReporter here.
        pass


class MetricsReporter:
    def __init__(self, testbed_name, testcase_name, test_run_id):
        self.testbed_name  = testbed_name
        self.testcase_name = testcase_name
        self.test_run_id   = test_run_id

    def emit_metrics(metrics: TestMetrics):
        # to be implemented
        pass
