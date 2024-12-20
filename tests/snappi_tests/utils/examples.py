import logging
import json
import datetime
import time

from typing import List, Dict, Union
from metrics import GaugeMetric, MetricsReporter
from reporter_factory import TelemetryReporterFactory

def main():
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-ABCD         1Z011010112349Q        01          12.09          18.38       222.00  OK        green
    PSU 2  PWR-ABCD         1Z011010156787X        01          12.10          17.72       214.00  OK        green

    """
    resource_labels = {
        "testbed.id": "sonic_stress_testbed",
        "os.version": "11.2.3",
        "testcase": "stress_test1",
        "testrun.id": "202412101217"
    }

    # Create a MetricReporterFactory and build a MetricReporter
    factory = TelemetryReporterFactory()
    reporter = factory.create_metrics_reporter(resource_labels)

    scope_labels = {"device.id": "switch-A"}

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
    scope_labels["psu.id"] = "PSU 1"
    voltage.record(scope_labels, 12.09)
    current.record(scope_labels, 18.38)
    power.record(scope_labels, 222.00)

    # Pass metrics to the reporter
    scope_labels["psu.id"] = "PSU 2"
    voltage.record(scope_labels, 12.10)
    current.record(scope_labels, 17.72)
    power.record(scope_labels, 214.00)

    # Report all metrics at a specific timestamp
    reporter.report()

if __name__ == '__main__':
    main()

