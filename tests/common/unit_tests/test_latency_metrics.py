from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "latency_metrics.py"
SPEC = importlib.util.spec_from_file_location("unit_target_latency_metrics", MODULE_PATH)
latency_metrics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(latency_metrics)


class TestLatencyMetrics(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.metric_file = os.path.join(self.temp_directory.name, "latency.jsonl")
        latency_metrics.set_latency_metric_threshold(1000)
        latency_metrics.configure_latency_metric_file(self.metric_file)

    def tearDown(self):
        latency_metrics.close_latency_metric_file()
        latency_metrics.set_latency_metric_threshold(
            latency_metrics.DEFAULT_LATENCY_METRIC_THRESHOLD_MS
        )
        self.temp_directory.cleanup()

    def read_records(self):
        latency_metrics.close_latency_metric_file()
        with open(self.metric_file, encoding="utf-8") as metric_stream:
            return [json.loads(line) for line in metric_stream]

    def test_success_below_threshold_is_not_logged(self):
        logged = latency_metrics.log_latency_metric(
            "operation", 999, success=True
        )

        self.assertFalse(logged)
        self.assertEqual(self.read_records(), [])

    def test_failure_below_threshold_is_logged(self):
        logged = latency_metrics.log_latency_metric(
            "operation", 1.23456, success=False, host="server-1"
        )

        self.assertTrue(logged)
        payload = self.read_records()[0]
        self.assertEqual(payload["duration_ms"], 1.235)
        self.assertEqual(payload["host"], "server-1")
        self.assertEqual(payload["metric"], "operation")
        self.assertFalse(payload["success"])
        self.assertEqual(payload["process_id"], os.getpid())
        self.assertTrue(payload["timestamp"].endswith("Z"))

    def test_success_at_threshold_is_logged(self):
        logged = latency_metrics.log_latency_metric(
            "operation", 1000, success=True, phase="setup"
        )

        self.assertTrue(logged)
        self.assertEqual(self.read_records()[0]["phase"], "setup")

    def test_negative_threshold_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-negative"):
            latency_metrics.set_latency_metric_threshold(-1)

    def test_format_caller_normalizes_repository_test_path(self):
        caller = latency_metrics.format_caller(
            r"C:\repo\tests\common\utilities.py", "wait_until", 123
        )

        self.assertEqual(caller, "tests/common/utilities.py::wait_until#123")

    def test_worker_uses_separate_metric_file(self):
        latency_metrics.close_latency_metric_file()
        worker_metric_file = latency_metrics.configure_latency_metric_file(
            self.metric_file, run_id="run123", worker_id="gw2"
        )

        latency_metrics.log_latency_metric("operation", 1000)
        latency_metrics.close_latency_metric_file()

        self.assertTrue(worker_metric_file.endswith("latency_run123_gw2.jsonl"))
        with open(worker_metric_file, encoding="utf-8") as metric_stream:
            payload = json.loads(metric_stream.readline())
        self.assertEqual(payload["run_id"], "run123")
        self.assertEqual(payload["worker"], "gw2")

    def test_unconfigured_metrics_do_not_reach_standard_logs(self):
        latency_metrics.close_latency_metric_file()

        logged = latency_metrics.log_latency_metric(
            "operation", 1000, success=False
        )

        self.assertFalse(logged)

    def test_concurrent_records_remain_valid_json_lines(self):
        latency_metrics.set_latency_metric_threshold(0)

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(
                lambda sequence: latency_metrics.log_latency_metric(
                    "operation", 1, sequence=sequence
                ),
                range(100)
            ))

        records = self.read_records()
        self.assertEqual(len(records), 100)
        self.assertEqual({record["sequence"] for record in records}, set(range(100)))

    def test_child_process_file_is_merged_on_close(self):
        with patch.object(latency_metrics.os, "getpid", return_value=12345):
            latency_metrics.log_latency_metric("operation", 1000)

        child_metric_file = self.metric_file.replace(".jsonl", "_pid12345.jsonl")
        self.assertTrue(os.path.isfile(child_metric_file))

        records = self.read_records()
        self.assertEqual(records[0]["process_id"], 12345)
        self.assertFalse(os.path.exists(child_metric_file))

    def test_write_error_disables_metrics_without_raising(self):
        with self.assertLogs(latency_metrics.logger, level="WARNING") as captured_logs:
            with patch("builtins.open", side_effect=OSError("disk full")):
                logged = latency_metrics.log_latency_metric(
                    "operation", 1000, success=False
                )

        self.assertFalse(logged)
        self.assertIn("disk full", captured_logs.output[0])
        self.assertFalse(latency_metrics.log_latency_metric(
            "operation", 1000, success=False
        ))


if __name__ == "__main__":
    unittest.main()
