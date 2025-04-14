from datetime import datetime
from reporter_factory import TelemetryReporterFactory
from metric_definitions import *    #noqa: F401
from metrics import GaugeMetric


def main():
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-ABCD         1Z011010112349Q        01          12.09          18.38       222.00  OK        green
    PSU 2  PWR-ABCD         1Z011010156787X        01          12.01          17.72       214.00  OK        green

    """

    # user provided common labels
    common_labels = {
        METRIC_LABEL_TEST_CASE: "mock-case",
        METRIC_LABEL_TEST_FILE: "mock-test.py",
    }

    # infra provided common labels
    common_labels[METRIC_LABEL_TESTBED] = "TB-XYZ"
    common_labels[METRIC_LABEL_TEST_BUILD] = "2024.1103"

    now = datetime.now()
    today_date = now.strftime("%Y%m%d")
    current_time = now.strftime("%H:%M:%S")
    common_labels[METRIC_LABEL_TEST_JOBID] = f"{common_labels[METRIC_LABEL_TEST_CASE]}_{today_date}_{current_time}"

    # Create a MetricReporterFactory and build a PeriodicMetricsReporter
    periodic_reporter = TelemetryReporterFactory.create_periodic_metrics_reporter(common_labels)

    metric_labels = {METRIC_LABEL_DEVICE_ID: "switch-A"}

    # Create metrics
    voltage = GaugeMetric(name=METRIC_NAME_PSU_VOLTAGE,
                          description="Power supply unit voltage reading",
                          unit="V",
                          reporter=periodic_reporter)

    current = GaugeMetric(name=METRIC_NAME_PSU_CURRENT,
                          description="Power supply unit current reading",
                          unit="A",
                          reporter=periodic_reporter)

    power = GaugeMetric(name=METRIC_NAME_PSU_POWER,
                        description="Power supply unit power reading",
                        unit="W",
                        reporter=periodic_reporter)

    status = GaugeMetric(name=METRIC_NAME_PSU_STATUS,
                          description="Power supply unit status",
                          unit="N/A",
                          reporter=periodic_reporter)

    led = GaugeMetric(name=METRIC_NAME_PSU_LED,
                        description="Power supply unit LED state",
                        unit="N/A",
                        reporter=periodic_reporter)

    # Pass metrics to the reporter
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 1"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-ABCD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010112349Q"
    voltage.record(metric_labels, 12.09)
    current.record(metric_labels, 18.38)
    power.record(metric_labels, 222.00)
    status.record(metric_labels, PSU_STATUS.OK)
    led.record(metric_labels, LED_STATE.GREEN)

    # Pass metrics to the reporter
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 2"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-ABCD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010156787X"
    voltage.record(metric_labels, 12.01)
    current.record(metric_labels, 17.72)
    power.record(metric_labels, 214.00)
    status.record(metric_labels, PSU_STATUS.OK)
    led.record(metric_labels, LED_STATE.GREEN)

    # Report periodic metrics
    periodic_reporter.report()

    # Build a FinalMetricsReporter
    final_reporter = TelemetryReporterFactory.create_final_metrics_reporter(common_labels)

    # Create metrics
    bgp_port_restart = GaugeMetric(name=METRIC_NAME_BGP_CONVERGENCE_PORT_RESTART,
                          description="BGP convergence time when a port is shut down and start up",
                          unit="s",
                          reporter=final_reporter)
    bgp_container_restart = GaugeMetric(name=METRIC_NAME_BGP_CONVERGENCE_CONTAINER_RESTART,
                               description="BGP convergence time when the bgp container restarts",
                               unit="s",
                               reporter=final_reporter)
    bgp_nh_change = GaugeMetric(name=METRIC_NAME_BGP_CONVERGENCE_NEXTHOP_CHANGE,
                       description="BGP convergence time when nexthops change",
                       unit="s",
                       reporter=final_reporter)

    # reset metric_labels
    metric_labels = []
    metric_labels = {METRIC_LABEL_DEVICE_ID: "switch-A"}

    bgp_port_restart.record(metric_labels, 15)
    bgp_container_restart.record(metric_labels, 72)
    bgp_nh_change.record(metric_labels, 60)

    # Report final metrics
    final_reporter.report()


if __name__ == '__main__':
    main()
