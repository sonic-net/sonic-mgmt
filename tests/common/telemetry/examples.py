import logging
import json
import datetime
import time
import sys
import os
from typing import Dict, Final, List, Union

# Add the root directory of the project to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from snappi_tests.utils.metrics import *
from snappi_tests.utils.reporter_factory import TelemetryReporterFactory


def main():
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-ABCD         1Z011010112349Q        01          12.09          18.38       222.00  OK        green
    PSU 2  PWR-ABCD         1Z011010156787X        01          12.01          17.72       214.00  OK        green

    """
    resource_labels = {
        METRIC_LABEL_TESTBED: "TB-XYZ",
        METRIC_LABEL_TEST_BUILD: "2024.1103",
        METRIC_LABEL_TEST_CASE: "mock-case",
        METRIC_LABEL_TEST_FILE: "mock-test.py",
        METRIC_LABEL_TEST_JOBID: "2024_1225_0621"
    }

    # Create a MetricReporterFactory and build a MetricReporter
    factory = TelemetryReporterFactory()
    reporter = factory.create_periodic_metrics_reporter(resource_labels)

    scope_labels = {METRIC_LABEL_DEVICE_ID: "switch-A"}

    # Create a metric
    voltage = GaugeMetric(name = "Voltage",
                          description = "Power supply unit voltage reading",
                          unit = "V",
                          reporter = reporter)

    # Create a metric
    current = GaugeMetric(name = "Current",
                          description = "Power supply unit current reading",
                          unit = "A",
                          reporter = reporter)

    # Create a metric
    power = GaugeMetric(name = "Power",
                        description = "Power supply unit power reading",
                        unit = "W",
                        reporter = reporter)

    # Pass metrics to the reporter
    scope_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 1"
    scope_labels[METRIC_LABEL_COMPONENT_MODEL] = "PWR-ABCD"
    scope_labels[METRIC_LABEL_COMPONENT_SERIAL] = "1Z011010112349Q"
    voltage.record(scope_labels, 12.09)
    current.record(scope_labels, 18.38)
    power.record(scope_labels, 222.00)

    # Pass metrics to the reporter
    scope_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 2"
    scope_labels[METRIC_LABEL_COMPONENT_MODEL] = "PWR-ABCD"
    scope_labels[METRIC_LABEL_COMPONENT_SERIAL] = "1Z011010156787X"
    voltage.record(scope_labels, 12.01)
    current.record(scope_labels, 17.72)
    power.record(scope_labels, 214.00)

    # Report all metrics at a specific timestamp
    reporter.report()


if __name__ == '__main__':
    main()
