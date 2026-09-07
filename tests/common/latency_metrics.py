"""Structured latency metrics shared by the pytest test framework."""

import json


DEFAULT_LATENCY_METRIC_THRESHOLD_MS = 5000
_latency_metric_threshold_ms = DEFAULT_LATENCY_METRIC_THRESHOLD_MS


def format_caller(filename, function_name, line_number):
    """Return a stable source location for grouping metrics across runners."""
    normalized_filename = filename.replace("\\", "/")
    tests_marker = "/tests/"
    if tests_marker in normalized_filename:
        normalized_filename = "tests/" + normalized_filename.split(tests_marker, 1)[1]
    return "{}::{}#{}".format(normalized_filename, function_name, line_number)


def set_latency_metric_threshold(threshold_ms):
    """Set the minimum successful-operation duration that is logged."""
    if threshold_ms < 0:
        raise ValueError("Latency metric threshold must be non-negative")

    global _latency_metric_threshold_ms
    _latency_metric_threshold_ms = threshold_ms


def log_latency_metric(metric_logger, metric, duration_ms, success=True, **fields):
    """Log a structured metric for slow or failed framework operations."""
    success = bool(success)
    if success and duration_ms < _latency_metric_threshold_ms:
        return False

    record = dict(fields)
    record.update({
        "metric": metric,
        "duration_ms": round(duration_ms, 3),
        "success": success
    })
    metric_logger.info("METRIC %s", json.dumps(record, sort_keys=True))
    return True
