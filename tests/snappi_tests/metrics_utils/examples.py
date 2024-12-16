import logging
import json
import datetime
import time

from typing import List, Dict, Union
from metrics_accepter import Metric, GaugeMetric
from metrics_reporter import MetricReporterFactory, MetricsReporter

def main():
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-2422-HV-RED  6A011010142349Q        01          12.09          18.38       222.00  OK        green
    PSU 2  PWR-2422-HV-RED  6A011010142327X        01          12.10          17.72       214.00  OK        green

    """
    resource_labels = {
        "testbed.id": "sonic_stress_testbed",
        "os.version": "11.2.3",
        "testcase": "stress_test1",
        "testrun.id": "202412101217"
    }

    # Create a MetricReporterFactory and build a MetricReporter
    factory = MetricReporterFactory()
    reporter = factory.create_metrics_reporter(resource_labels)

    scope_labels = {
        "device.id": "str-7060x6-64pe-stress-02",
        "psu.id": "psu1",
        "model": "PWR-2422-HV-RED",
        "serial": "6A011010142349Q"}

    # Create a metric and pass it to the reporter
    vol = GaugeMetric(name = "Voltage",
                      description = "PSU voltage reading",
                      unit = "V",
                      reporter = reporter)
    vol.set_gauge_metric(scope_labels, 12.09)

    # Create a metric and pass it to the reporter
    cur = GaugeMetric(name = "Current",
                      description = "PSU current reading",
                      unit = "A",
                      reporter = reporter)
    cur.set_gauge_metric(scope_labels, 18.38)

    # Create a metric and pass it to the reporter
    power = GaugeMetric(name = "Power",
                        description = "PSU power reading",
                        unit = "W",
                        reporter = reporter)
    power.set_gauge_metric(scope_labels, 222.00)

    # Report all metrics at a specific timestamp
    reporter.report()

if __name__ == '__main__':
    main()

