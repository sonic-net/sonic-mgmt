"""Structured latency metrics shared by the pytest test framework."""

from datetime import datetime, timezone
import glob
import json
import logging
import os
import shutil
import threading


DEFAULT_LATENCY_METRIC_THRESHOLD_MS = 5000
DEFAULT_LATENCY_METRIC_FILE = os.path.join("logs", "framework_latency_metrics.jsonl")
logger = logging.getLogger(__name__)
_latency_metric_threshold_ms = DEFAULT_LATENCY_METRIC_THRESHOLD_MS
_latency_metric_file = None
_latency_metric_worker_id = None
_latency_metric_run_id = None
_latency_metric_owner_pid = None
_latency_metric_error_reported = False
_latency_metric_write_lock = threading.RLock()


def _reset_latency_metric_write_lock():
    global _latency_metric_write_lock
    _latency_metric_write_lock = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_latency_metric_write_lock)


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


def _scoped_metric_file(metric_file, run_id, worker_id):
    suffixes = [suffix for suffix in (run_id, worker_id) if suffix]
    if not suffixes:
        return metric_file
    file_root, file_extension = os.path.splitext(metric_file)
    return "{}_{}{}".format(file_root, "_".join(suffixes), file_extension)


def _process_metric_file(metric_file, process_id):
    file_root, file_extension = os.path.splitext(metric_file)
    return "{}_pid{}{}".format(file_root, process_id, file_extension)


def _process_metric_pattern(metric_file):
    file_root, file_extension = os.path.splitext(metric_file)
    return "{}_pid*{}".format(file_root, file_extension)


def _disable_latency_metrics(error):
    global _latency_metric_file, _latency_metric_error_reported
    with _latency_metric_write_lock:
        if not _latency_metric_error_reported:
            logger.warning("Disabling framework latency metrics after file I/O error: %s", error)
            _latency_metric_error_reported = True
        _latency_metric_file = None


def close_latency_metric_file():
    """Merge child-process records and disable latency metric writes."""
    global _latency_metric_file, _latency_metric_worker_id, _latency_metric_run_id
    global _latency_metric_owner_pid, _latency_metric_error_reported
    with _latency_metric_write_lock:
        try:
            if _latency_metric_file is not None and os.getpid() == _latency_metric_owner_pid:
                process_files = sorted(glob.glob(_process_metric_pattern(_latency_metric_file)))
                if process_files:
                    with open(_latency_metric_file, "ab") as metric_stream:
                        for process_file in process_files:
                            with open(process_file, "rb") as process_stream:
                                shutil.copyfileobj(process_stream, metric_stream)
                            os.remove(process_file)
        except OSError as error:
            if not _latency_metric_error_reported:
                logger.warning("Unable to merge framework latency metric files: %s", error)
                _latency_metric_error_reported = True
        finally:
            _latency_metric_file = None
            _latency_metric_worker_id = None
            _latency_metric_run_id = None
            _latency_metric_owner_pid = None


def configure_latency_metric_file(metric_file, run_id=None, worker_id=None):
    """Configure the JSONL file used for structured latency records."""
    if not metric_file:
        raise ValueError("Latency metric file must not be empty")

    close_latency_metric_file()
    resolved_metric_file = os.path.abspath(_scoped_metric_file(metric_file, run_id, worker_id))
    metric_directory = os.path.dirname(resolved_metric_file)
    os.makedirs(metric_directory, exist_ok=True)
    with open(resolved_metric_file, "x", encoding="utf-8"):
        pass

    global _latency_metric_file, _latency_metric_worker_id, _latency_metric_run_id
    global _latency_metric_owner_pid, _latency_metric_error_reported
    with _latency_metric_write_lock:
        _latency_metric_file = resolved_metric_file
        _latency_metric_worker_id = worker_id
        _latency_metric_run_id = run_id
        _latency_metric_owner_pid = os.getpid()
        _latency_metric_error_reported = False
    return resolved_metric_file


def log_latency_metric(metric, duration_ms, success=True, **fields):
    """Log a structured metric for slow or failed framework operations."""
    success = bool(success)
    if success and duration_ms < _latency_metric_threshold_ms:
        return False

    process_id = os.getpid()
    try:
        with _latency_metric_write_lock:
            if _latency_metric_file is None:
                return False
            record = dict(fields)
            record.update({
                "metric": metric,
                "duration_ms": round(duration_ms, 3),
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "process_id": process_id
            })
            if _latency_metric_run_id:
                record["run_id"] = _latency_metric_run_id
            if _latency_metric_worker_id:
                record["worker"] = _latency_metric_worker_id
            metric_file = _latency_metric_file
            if process_id != _latency_metric_owner_pid:
                metric_file = _process_metric_file(metric_file, process_id)
            with open(metric_file, "a", encoding="utf-8", newline="\n") as metric_stream:
                metric_stream.write("{}\n".format(json.dumps(record, sort_keys=True)))
    except OSError as error:
        _disable_latency_metrics(error)
        return False
    return True
