# This file defines the interfaces that snappi tests accept external metrics.

#  Metrics data are organized into the hierarchies below
#  ResourceMetrics
#    ├── ResourceID
#    └── ScopeMetrics
#       ├── ScopeID
#       └── Metric
#          ├── Name
#          ├── Description
#          ├── Unit
#          ├── metadata
#          └── data
#             └── Gauge
#
# A ResourceMetrics has its ID and a list of ScopeMetrics objects.
# A ScopeMetrics    has its ID and a list of Metric objects.
# A Metric has several attributes and data. So far we only have Gauge type data.
# A Gauge has a list of NumberDataPoint objects.
# A NumberDataPoint has its label, value, flags and the timestamp at which the data was collected.
#                         +---------------------+
#                         | DataPoint 1         |
#                         | +---------+ +-----+ |
#               +-----+   | |timestamp| |label| |
#               |  1  |-->| +---------+ +-----+ |
#               +-----+   |                     |
#               |  .  |   | +-----+ +-----+     |
#               |  .  |   | |value| |flags|     |
#               |  .  |   | +-----+ +-----+     |
#               |  .  |   +---------------------+
#               |  .  |              .
#               |  .  |              .
#               |  .  |              .
#               |  .  |   +---------------------+
#               |  .  |   | DataPoint M         |
#               +-----+   | +---------+ +-----+ |
#               |  M  |-->| |timestamp| |label| |
#               +-----+   | +---------+ +-----+ |
#                         |                     |
#                         | +-----+ +-----+     |
#                         | |value| |flags|     |
#                         | +-----+ +-----+     |
#                         +---------------------+

from typing import List, Dict, Union

class NumberDataPoint:
    def __init__(self, time_unix_nano: int, label: List[Dict[str, str]], value: Union[int, float], flags: int = None):
        self.time_unix_nano = time_unix_nano    # UNIX Epoch time in nanoseconds
        self.label          = label             # The key of key-value pairs in dictionaries
        self.value          = value             # Metric value (can be double or integer)
        self.flags          = flags             # Optional flags

    def __repr__(self):
        return (f"NumberDataPoint(label={self.label}, "
                f"time_unix_nano={self.time_unix_nano}, value={self.value}, flags={self.flags})")


class Gauge:
    def __init__(self):
        self.data_points = []  # List of NumberDataPoint objects

    def add_data_point(self, data_point):
        self.data_points.append(data_point)

    def __repr__(self):
        return f"Gauge(data_points={self.data_points})"


class Metric:
    def __init__(self, name, description, unit, data_points, metadata=None):
        self.name        = name            # Metric name
        self.description = description     # Metric description
        self.unit        = unit            # Metric unit (e.g., seconds, bytes)
        self.data        = data            # Can be Gauge only
        self.metadata    = metadata or {}  # Default to an empty dictionary if None

    def __repr__(self):
        return (f"Metric(name={self.name}, description={self.description}, "
                f"unit={self.unit}, data={self.data})")


# a ScopeMetrics object's ID is device_id
class ScopeMetrics:
    def __init__(self, device_id):
        self.device_id = device_id
        self.metrics   = []

    def add_metric(self, metric):
        self.metrics.append(metric)

    def __repr__(self):
        return f"ScopeMetrics(scope={self.scope}, metrics={self.metrics})"


# a ResourceMetrics object's ID is test_run_id
class ResourceMetrics:
    def __init__(self, test_run_id, os_version):
        self.test_run_id   = test_run_id
        self.os_version    = os_version
        self.scope_metrics = []

    def add_scope_metrics(self, scope_metric):
        self.scope_metrics.append(scope_metric)

    def __repr__(self):
        return f"ResourceMetrics(resource={self.resource}, scope_metrics={self.scope_metrics})"


