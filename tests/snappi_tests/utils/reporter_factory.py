import logging
import json
import datetime
import time

from typing import List, Dict, Union
from metrics import PeriodicMetricsReporter, FinalMetricsReporter

class TelemetryReporterFactory:
    def __init__(self):
        return

    def create_periodic_metrics_reporter(self, resource_labels: Dict[str, str]):
        return (PeriodicMetricsReporter(resource_labels))

    def create_final_metrics_reporter(self, resource_labels: Dict[str, str]):
        return (FinalMetricsReporter(resource_labels))
