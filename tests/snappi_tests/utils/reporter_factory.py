
import logging
import json
import datetime
import time
from typing import List, Dict, Union

from metrics import MetricsReporter, TestResultsReporter

class TelemetryReporterFactory:
    def __init__(self):
        return

    def create_metrics_reporter(self, resource_labels: Dict[str, str]):
        return (MetricsReporter(resource_labels))

    def create_test_results_reporter(self, resource_labels: Dict[str, str]):
        return (RecordsReporter(resource_labels))


