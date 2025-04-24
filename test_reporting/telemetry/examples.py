from reporter_factory import TelemetryReporterFactory
from metrics import (
    GaugeMetric,
    METRIC_LABEL_TESTBED,
    METRIC_LABEL_TEST_BUILD,
    METRIC_LABEL_TEST_CASE,
    METRIC_LABEL_TEST_FILE,
    METRIC_LABEL_TEST_JOBID,
    METRIC_LABEL_DEVICE_ID,
    METRIC_LABEL_DEVICE_PSU_ID,
    METRIC_LABEL_DEVICE_PSU_MODEL,
    METRIC_LABEL_DEVICE_PSU_SERIAL
)


def main():
    """

    PSU    Model            Serial             HW Rev    Voltage (V)    Current (A)    Power (W)  Status    LED
    -----  ---------------  ---------------  --------  -------------  -------------  -----------  --------  -----
    PSU 1  PWR-ABCD         1Z011010112349Q        01          12.09          18.38       222.00  OK        green
    PSU 2  PWR-ABCD         1Z011010156787X        01          12.01          17.72       214.00  OK        green

    """
    common_labels = {
        METRIC_LABEL_TESTBED: "TB-XYZ",
        METRIC_LABEL_TEST_BUILD: "2024.1103",
        METRIC_LABEL_TEST_CASE: "mock-case",
        METRIC_LABEL_TEST_FILE: "mock-test.py",
        METRIC_LABEL_TEST_JOBID: "2024_1225_0621"
    }

    # Create a MetricReporterFactory and build a MetricReporter
    reporter = TelemetryReporterFactory.create_periodic_metrics_reporter(common_labels)

    metric_labels = {METRIC_LABEL_DEVICE_ID: "switch-A"}

    # Create a metric
    voltage = GaugeMetric(name="Voltage",
                          description="Power supply unit voltage reading",
                          unit="V",
                          reporter=reporter)

    # Create a metric
    current = GaugeMetric(name="Current",
                          description="Power supply unit current reading",
                          unit="A",
                          reporter=reporter)

    # Create a metric
    power = GaugeMetric(name="Power",
                        description="Power supply unit power reading",
                        unit="W",
                        reporter=reporter)

    # Pass metrics to the reporter
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 1"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-ABCD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010112349Q"
    voltage.record(metric_labels, 12.09)
    current.record(metric_labels, 18.38)
    power.record(metric_labels, 222.00)

    # Pass metrics to the reporter
    metric_labels[METRIC_LABEL_DEVICE_PSU_ID] = "PSU 2"
    metric_labels[METRIC_LABEL_DEVICE_PSU_MODEL] = "PWR-ABCD"
    metric_labels[METRIC_LABEL_DEVICE_PSU_SERIAL] = "1Z011010156787X"
    voltage.record(metric_labels, 12.01)
    current.record(metric_labels, 17.72)
    power.record(metric_labels, 214.00)

    # Report all metrics at a specific timestamp
    reporter.report()


if __name__ == '__main__':
    main()
