import os
from datetime import datetime
from typing import Dict
from reporter_factory import TelemetryReporterFactory
from metrics import GaugeMetric
# flake8: noqa
from metric_definitions import *


def MetricReporter():
    # user provided common labels

    # In this example, the test case is hardcoded. In the actual test script, we can use
    # request.node.originalname to dynamically retrieve the name of the running test case.
    common_labels = {
        METRIC_LABEL_TEST_CASE: "mock-case",
    }

    # infra provided common labels
    file_name = os.path.basename(__file__)
    common_labels[METRIC_LABEL_TEST_FILE] = file_name
    common_labels[METRIC_LABEL_TESTBED] = "TB-XYZ"
    common_labels[METRIC_LABEL_TEST_BUILD] = "2024.1103"

    now = datetime.now()
    today_date = now.strftime("%Y%m%d")
    current_time = now.strftime("%H:%M:%S")
    common_labels[METRIC_LABEL_TEST_JOBID] = f"{common_labels[METRIC_LABEL_TEST_CASE]}_{today_date}_{current_time}"

    # Create a MetricReporterFactory and build a PeriodicMetricsReporter
    periodic_reporter = TelemetryReporterFactory.create_periodic_metrics_reporter(common_labels)
    final_reporter = TelemetryReporterFactory.create_final_metrics_reporter(common_labels)

    return periodic_reporter, final_reporter


def psuMetrics(metrics_reporter) -> Dict[str, GaugeMetric]:

    # Create metrics
    voltage = GaugeMetric(name=METRIC_NAME_PSU_VOLTAGE,
                          description="Power supply unit voltage reading",
                          unit="V",
                          reporter=metrics_reporter)
    current = GaugeMetric(name=METRIC_NAME_PSU_CURRENT,
                          description="Power supply unit current reading",
                          unit="A",
                          reporter=metrics_reporter)
    power = GaugeMetric(name=METRIC_NAME_PSU_POWER,
                        description="Power supply unit power reading",
                        unit="W",
                        reporter=metrics_reporter)
    status = GaugeMetric(name=METRIC_NAME_PSU_STATUS,
                         description="Power supply unit status",
                         unit="N/A",
                         reporter=metrics_reporter)
    led = GaugeMetric(name=METRIC_NAME_PSU_LED,
                      description="Power supply unit LED state",
                      unit="N/A",
                      reporter=metrics_reporter)

    return {
        METRIC_NAME_PSU_VOLTAGE: voltage,
        METRIC_NAME_PSU_CURRENT: current,
        METRIC_NAME_PSU_POWER: power,
        METRIC_NAME_PSU_STATUS: status,
        METRIC_NAME_PSU_LED: led,
    }


def bgpMetrics(metrics_reporter) -> Dict[str, GaugeMetric]:

    # Create metrics
    bgp_port_restart = GaugeMetric(name=METRIC_NAME_BGP_CONVERGENCE_TIME_PORT_RESTART,
                                   description="BGP convergence time when a port is shut down and start up",
                                   unit="s",
                                   reporter=metrics_reporter)
    bgp_container_restart = GaugeMetric(name=METRIC_NAME_BGP_CONVERGENCE_TIME_CONTAINER_RESTART,
                                        description="BGP convergence time when the bgp container restarts",
                                        unit="s",
                                        reporter=metrics_reporter)
    bgp_nh_change = GaugeMetric(name=METRIC_NAME_BGP_CONVERGENCE_TIME_NEXTHOP_CHANGE,
                                description="BGP convergence time when nexthops change",
                                unit="s",
                                reporter=metrics_reporter)

    return {
        METRIC_NAME_BGP_CONVERGENCE_TIME_PORT_RESTART: bgp_port_restart,
        METRIC_NAME_BGP_CONVERGENCE_TIME_CONTAINER_RESTART: bgp_container_restart,
        METRIC_NAME_BGP_CONVERGENCE_TIME_NEXTHOP_CHANGE: bgp_nh_change,
    }


def test_telemetry_example1(metrics_reporter, psu_metrics):
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-ABCD         1Z011010112349Q        01          12.09          18.38       222.00  OK        green
    PSU 2  PWR-ABCD         1Z011010156787X        01          12.01          17.72       214.00  OK        green

    """
    # Set shared metric labels
    metric_labels = {METRIC_LABEL_DEVICE_ID: "switch-A"}

    # Set non-shared metric labels
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 1"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-ABCD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010112349Q"

    # Set metric values
    psu_metrics[METRIC_NAME_PSU_VOLTAGE].record(metric_labels, 12.09)
    psu_metrics[METRIC_NAME_PSU_CURRENT].record(metric_labels, 18.38)
    psu_metrics[METRIC_NAME_PSU_POWER].record(metric_labels, 222.00)
    psu_metrics[METRIC_NAME_PSU_STATUS].record(metric_labels, PSU_STATUS.OK.value)
    psu_metrics[METRIC_NAME_PSU_LED].record(metric_labels, LED_STATE.GREEN.value)

    # Set non-shared metric labels
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 2"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-ABCD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010156787X"

    # Set metric values
    psu_metrics[METRIC_NAME_PSU_VOLTAGE].record(metric_labels, 12.01)
    psu_metrics[METRIC_NAME_PSU_CURRENT].record(metric_labels, 17.72)
    psu_metrics[METRIC_NAME_PSU_POWER].record(metric_labels, 214.00)
    psu_metrics[METRIC_NAME_PSU_STATUS].record(metric_labels, PSU_STATUS.OK.value)
    psu_metrics[METRIC_NAME_PSU_LED].record(metric_labels, LED_STATE.GREEN.value)

    # Pass metrics to the reporter
    metrics_reporter.report()


def test_telemetry_example2(metrics_reporter, psu_metrics):
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-DECD         1Z0110101ASDF9Q        01          12.08          19.12       231.00  OK        green
    PSU 2  PWR-DECD         1Z011010153FE7X        01          12.07          18.75       226.00  OK        green

    """
    # Set shared metric labels
    metric_labels = {METRIC_LABEL_DEVICE_ID: "switch-Z"}

    # Set non-shared metric labels
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 1"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-DECD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z0110101ASDF9Q"

    # Set metric values
    psu_metrics[METRIC_NAME_PSU_VOLTAGE].record(metric_labels, 12.08)
    psu_metrics[METRIC_NAME_PSU_CURRENT].record(metric_labels, 19.12)
    psu_metrics[METRIC_NAME_PSU_POWER].record(metric_labels, 231.00)
    psu_metrics[METRIC_NAME_PSU_STATUS].record(metric_labels, PSU_STATUS.OK.value)
    psu_metrics[METRIC_NAME_PSU_LED].record(metric_labels, LED_STATE.GREEN.value)

    # Set non-shared metric labels
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 2"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-DECD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010153FE7X"

    # Set metric values
    psu_metrics[METRIC_NAME_PSU_VOLTAGE].record(metric_labels, 12.07)
    psu_metrics[METRIC_NAME_PSU_CURRENT].record(metric_labels, 18.75)
    psu_metrics[METRIC_NAME_PSU_POWER].record(metric_labels, 226.00)
    psu_metrics[METRIC_NAME_PSU_STATUS].record(metric_labels, PSU_STATUS.OK.value)
    psu_metrics[METRIC_NAME_PSU_LED].record(metric_labels, LED_STATE.GREEN.value)

    # Pass metrics to the reporter
    metrics_reporter.report()


def test_telemetry_example3(metrics_reporter, bgp_metrics):

    # Set shared metric labels
    metric_labels = {METRIC_LABEL_DEVICE_ID: "switch-A"}

    # Set metric values
    bgp_metrics[METRIC_NAME_BGP_CONVERGENCE_TIME_PORT_RESTART].record(metric_labels, 15)
    bgp_metrics[METRIC_NAME_BGP_CONVERGENCE_TIME_CONTAINER_RESTART].record(metric_labels, 72)
    bgp_metrics[METRIC_NAME_BGP_CONVERGENCE_TIME_NEXTHOP_CHANGE].record(metric_labels, 60)

    # Pass metrics to the reporter
    metrics_reporter.report()


def main():

    # Mimic pytest object resolution to create the metrics reporter and metrics automatically before running the tests.
    periodic_reporter, final_reporter = MetricReporter()
    psu_metrics = psuMetrics(periodic_reporter)
    bgp_metrics = bgpMetrics(final_reporter)

    # Report telemetry metrics
    test_telemetry_example1(periodic_reporter, psu_metrics)
    test_telemetry_example2(periodic_reporter, psu_metrics)
    test_telemetry_example3(final_reporter, bgp_metrics)


if __name__ == '__main__':
    main()
