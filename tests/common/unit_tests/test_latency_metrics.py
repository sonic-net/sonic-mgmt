import importlib.util
import json
import logging
from pathlib import Path
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "latency_metrics.py"
SPEC = importlib.util.spec_from_file_location("unit_target_latency_metrics", MODULE_PATH)
latency_metrics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(latency_metrics)

LOGGER = logging.getLogger(__name__)


class TestLatencyMetrics(unittest.TestCase):
    def setUp(self):
        latency_metrics.set_latency_metric_threshold(1000)

    def tearDown(self):
        latency_metrics.set_latency_metric_threshold(
            latency_metrics.DEFAULT_LATENCY_METRIC_THRESHOLD_MS
        )

    def test_success_below_threshold_is_not_logged(self):
        with patch.object(LOGGER, "info") as log_info:
            logged = latency_metrics.log_latency_metric(
                LOGGER, "operation", 999, success=True
            )

        self.assertFalse(logged)
        log_info.assert_not_called()

    def test_failure_below_threshold_is_logged(self):
        with patch.object(LOGGER, "info") as log_info:
            logged = latency_metrics.log_latency_metric(
                LOGGER, "operation", 1.23456, success=False, host="server-1"
            )

        self.assertTrue(logged)
        payload = json.loads(log_info.call_args.args[1])
        self.assertEqual(payload, {
            "duration_ms": 1.235,
            "host": "server-1",
            "metric": "operation",
            "success": False
        })

    def test_success_at_threshold_is_logged(self):
        with patch.object(LOGGER, "info") as log_info:
            logged = latency_metrics.log_latency_metric(
                LOGGER, "operation", 1000, success=True, phase="setup"
            )

        self.assertTrue(logged)
        self.assertIn('"phase": "setup"', log_info.call_args.args[1])

    def test_negative_threshold_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-negative"):
            latency_metrics.set_latency_metric_threshold(-1)

    def test_format_caller_normalizes_repository_test_path(self):
        caller = latency_metrics.format_caller(
            r"C:\repo\tests\common\utilities.py", "wait_until", 123
        )

        self.assertEqual(caller, "tests/common/utilities.py::wait_until#123")


if __name__ == "__main__":
    unittest.main()
