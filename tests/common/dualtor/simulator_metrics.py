"""
Helpers for parsing and summarizing DualToR simulator metrics.
"""
import json
import logging
from collections import defaultdict


logger = logging.getLogger(__name__)


def percentile(values, percentile_value):
    """Return a nearest-rank percentile from a non-empty list."""
    ordered = sorted(values)
    rank = max(1, int((percentile_value * len(ordered) + 99) // 100))
    return ordered[min(rank - 1, len(ordered) - 1)]


def read_metric_records(log_file):
    """Read structured METRIC records from a simulator log file."""
    records = []
    with open(log_file, encoding="utf-8", errors="replace") as stream:
        for line in stream:
            _, separator, payload = line.partition("METRIC ")
            if not separator:
                continue
            try:
                records.append(json.loads(payload))
            except json.JSONDecodeError:
                logger.warning("Failed to parse metric line from %s: %s", log_file, line.rstrip())
    return records


def summarize_metric_records(records):
    """Build a compact per-metric latency summary for CustomMsg."""
    durations = defaultdict(list)
    failures = defaultdict(int)
    for record in records:
        metric_name = record.get("metric")
        duration_ms = record.get("duration_ms")
        if not metric_name or not isinstance(duration_ms, (int, float)):
            continue
        durations[metric_name].append(duration_ms)
        status_code = record.get("status_code")
        failed = (
            record.get("success") is False or
            record.get("return_code") not in (None, 0) or
            isinstance(status_code, int) and status_code >= 400
        )
        if failed:
            failures[metric_name] += 1

    summary = {}
    for metric_name, values in durations.items():
        summary[metric_name] = {
            "count": len(values),
            "failures": failures[metric_name],
            "p50_ms": round(percentile(values, 50), 3),
            "p95_ms": round(percentile(values, 95), 3),
            "p99_ms": round(percentile(values, 99), 3),
            "max_ms": round(max(values), 3)
        }
    return summary
