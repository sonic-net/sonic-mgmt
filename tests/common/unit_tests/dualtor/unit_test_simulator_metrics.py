import importlib.util
import json
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2] /
    "dualtor/simulator_metrics.py"
)
SPEC = importlib.util.spec_from_file_location(
    "unit_target_simulator_metrics", MODULE_PATH
)
SIMULATOR_METRICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIMULATOR_METRICS)


def test_percentile_uses_nearest_rank():
    values = [1, 2, 3, 4]

    assert SIMULATOR_METRICS.percentile(values, 50) == 2
    assert SIMULATOR_METRICS.percentile(values, 95) == 4
    assert SIMULATOR_METRICS.percentile(values, 99) == 4


def test_summarize_metric_records_counts_failures():
    records = [
        {
            "metric": "mux_http_request",
            "duration_ms": 100,
            "success": True
        },
        {
            "metric": "mux_http_request",
            "duration_ms": 300,
            "success": False
        },
        {
            "metric": "mux_ovs_command",
            "duration_ms": 50,
            "return_code": 0
        },
        {
            "metric": "mux_ovs_command",
            "duration_ms": 70,
            "return_code": 1
        }
    ]

    summary = SIMULATOR_METRICS.summarize_metric_records(records)

    assert summary["mux_http_request"] == {
        "count": 2,
        "failures": 1,
        "p50_ms": 100,
        "p95_ms": 300,
        "p99_ms": 300,
        "max_ms": 300
    }
    assert summary["mux_ovs_command"] == {
        "count": 2,
        "failures": 1,
        "p50_ms": 50,
        "p95_ms": 70,
        "p99_ms": 70,
        "max_ms": 70
    }


def test_read_metric_records_ignores_non_metric_lines(tmp_path):
    metric = {
        "metric": "nic_grpc_request",
        "duration_ms": 12.5
    }
    log_file = tmp_path / "nic_simulator.log"
    log_file.write_text(
        "ordinary log line\n"
        "2026-08-26 INFO METRIC {}\n".format(json.dumps(metric)),
        encoding="utf-8"
    )

    assert SIMULATOR_METRICS.read_metric_records(log_file) == [metric]
