from typing import Dict
from metrics import PeriodicMetricsReporter, FinalMetricsReporter


class TelemetryReporterFactory:
    def __init__(self):
        return

    @staticmethod
    def create_periodic_metrics_reporter(common_labels: Dict[str, str]):
        return (PeriodicMetricsReporter(common_labels))

    @staticmethod
    def create_final_metrics_reporter(common_labels: Dict[str, str]):
        return (FinalMetricsReporter(common_labels))
