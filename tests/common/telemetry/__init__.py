"""
SONiC Mgmt Test Telemetry Framework

"""

# Base classes
from .base import Reporter, Metric, MetricCollection, MetricDefinition, default_value_convertor

# Metric types
from .metrics import GaugeMetric, HistogramMetric

# Reporters
from .reporters import TSReporter, DBReporter

# Device metric collections
from .metrics.device import (
    DevicePortMetrics, DevicePSUMetrics, DeviceQueueMetrics,
    DeviceTemperatureMetrics, DeviceFanMetrics
)

# Constants and labels
from .constants import (
    # Common Labels
    METRIC_LABEL_DEVICE_ID, METRIC_LABEL_DEVICE_PORT_ID, METRIC_LABEL_DEVICE_PSU_ID,
    METRIC_LABEL_DEVICE_QUEUE_ID, METRIC_LABEL_DEVICE_SENSOR_ID, METRIC_LABEL_DEVICE_FAN_ID,

    # Port Metrics
    METRIC_NAME_PORT_RX_BPS, METRIC_NAME_PORT_TX_BPS, METRIC_NAME_PORT_RX_UTIL, METRIC_NAME_PORT_TX_UTIL,

    # PSU Metrics
    METRIC_NAME_PSU_VOLTAGE, METRIC_NAME_PSU_CURRENT, METRIC_NAME_PSU_POWER,

    # BGP Metrics
    METRIC_NAME_BGP_CONVERGENCE_TIME_PORT_RESTART,

    # Units
    UNIT_SECONDS, UNIT_BYTES_PER_SECOND, UNIT_PERCENT, UNIT_COUNT
)

# Pytest fixtures (imported for convenience, but should be used via conftest.py)
from .fixtures import ts_reporter, db_reporter

# Version information
__version__ = "1.0.0"

# Public API - define what gets imported with "from common.telemetry import *"
__all__ = [
    # Base classes
    'Reporter', 'Metric', 'MetricCollection', 'MetricDefinition', 'default_value_convertor',

    # Metric types
    'GaugeMetric', 'HistogramMetric',

    # Reporters
    'TSReporter', 'DBReporter',

    # Device metrics
    'DevicePortMetrics', 'DevicePSUMetrics', 'DeviceQueueMetrics',
    'DeviceTemperatureMetrics', 'DeviceFanMetrics',

    # Essential constants
    'METRIC_LABEL_DEVICE_ID', 'METRIC_LABEL_DEVICE_PORT_ID', 'METRIC_LABEL_DEVICE_PSU_ID',
    'METRIC_LABEL_DEVICE_QUEUE_ID', 'METRIC_LABEL_DEVICE_SENSOR_ID', 'METRIC_LABEL_DEVICE_FAN_ID',

    # Port metric names
    'METRIC_NAME_PORT_RX_BPS', 'METRIC_NAME_PORT_TX_BPS', 'METRIC_NAME_PORT_RX_UTIL', 'METRIC_NAME_PORT_TX_UTIL',

    # PSU metric names
    'METRIC_NAME_PSU_VOLTAGE', 'METRIC_NAME_PSU_CURRENT', 'METRIC_NAME_PSU_POWER',

    # BGP metric names
    'METRIC_NAME_BGP_CONVERGENCE_TIME_PORT_RESTART',

    # Common units
    'UNIT_SECONDS', 'UNIT_PERCENT', 'UNIT_COUNT', 'UNIT_BYTES_PER_SECOND',

    # Pytest fixtures
    'ts_reporter', 'db_reporter'
]
