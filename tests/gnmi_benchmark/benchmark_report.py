"""BenchmarkReport and its statistics; no execution or DUT access."""

import math
import json
import re
import logging
import uuid
from collections import Counter
from bisect import bisect_left
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

logger = logging.getLogger(__name__)


class BenchmarkReport:
    def __init__(self, device=None, connection_type="TLS"):
        self.device = device or {}
        self.connection_type = connection_type
        self.cid = str(uuid.uuid4())
        self.measurement = None
        self.execution = {}
        self.resources = []

    def generate(self, *, samples, warmup, connection_ready_seconds, resources, marker, blaster, profile=None):
        """Derive report fields from raw phase data; never control test execution."""
        self.measurement, self.execution = _phase_metrics(samples)
        summary = dict(marker=marker, completed=0, admission_seconds=0)
        if warmup is not None:
            measured, execution = _phase_metrics(warmup)
            summary.update(admission_seconds=warmup["duration_seconds"], elapsed_seconds=measured["elapsed_seconds"],
                           drain_seconds=execution["drain_seconds"], iteration_status_counts=measured["statuses"],
                           response_errors=measured["response_errors"], completed=sum(measured["statuses"].values()),
                           dropped=warmup["dropped_capacity"] + warmup["dropped_late"])
        self.execution.update(
            warmup=summary, connection_ready_seconds=connection_ready_seconds,
            connection_setup="ready_before_load" if connection_ready_seconds is not None else "included_in_first_rpc")
        self.resources = resources
        self.marker, self.blaster = marker, blaster
        self.profile = dict(profile or {})
        return self

    @property
    def counts(self):
        statuses = Counter()
        errors = 0
        for samples in self.measurement["rpc"].values():
            statuses.update(samples["statuses"])
            errors += samples["response_errors"]
        return _outcome_counts(statuses, errors)

    @property
    def failed(self):
        scheduling = self.execution.get("scheduling", {})
        slow = any(value > 1000 for samples in self.measurement["rpc"].values() for value in samples["latencies"])
        return bool(self.counts["failed"] or slow or scheduling.get("dropped_capacity", 0)
                    or scheduling.get("dropped_late", 0))

    def to_dict(self):
        if self.measurement is None:
            raise RuntimeError("No measured phase has completed")
        return _build_report(self)

    def write(self, output_dir):
        report = self.to_dict()
        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "{}-report.json".format(self.cid)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        logger.info("GNMI_BENCHMARK_JSON %s", json.dumps(report, separators=(",", ":"), sort_keys=True))
        return str(path)


def _phase_metrics(samples):
    """Report semantics live here; input contains no live scheduler/worker objects."""
    workers = samples["workers"]
    duration, rate = samples["duration_seconds"], samples["rate"]
    start_ns = samples["start_ns"] if duration or rate else min(w["started_ns"] for w in workers)
    start_ts = samples["start_ts"] if duration or rate else min(w["started_ts"] for w in workers)
    finished_ts = samples["finished_ts"] or max(w["finished_ts"] for w in workers)
    end_ns = max([w["finished_ns"] for w in workers] +
                 [samples["start_ns"] + int(samples["admission_elapsed"] * 1_000_000_000)])
    elapsed = (end_ns - start_ns) / 1_000_000_000
    drain = max(0, elapsed - (samples["admission_elapsed"] if rate else duration)) if rate or duration else 0
    statuses = Counter()
    for worker in workers:
        statuses.update(worker["statuses"])
    rpc = {}
    for worker in workers:
        for method, rpc_samples in worker["rpc"].items():
            if method not in rpc:
                rpc[method] = dict(statuses=Counter(), response_errors=0, latencies=[])
            rpc[method]["statuses"].update(rpc_samples["statuses"])
            rpc[method]["response_errors"] += rpc_samples["response_errors"]
            rpc[method]["latencies"].extend(rpc_samples["latencies"])
    measurement = dict(started_ts=start_ts.isoformat(), finished_ts=finished_ts.isoformat(), elapsed_seconds=elapsed,
                       statuses=dict(statuses), response_errors=sum(w["response_errors"] for w in workers),
                       rpc=rpc)
    successes = sum(w["successful_in_window"] for w in workers)
    execution = dict(
        concurrency=samples["concurrency"], traffic_pattern="open-loop" if rate else "closed-loop",
        mode="duration" if duration else "count", admission_seconds=duration or None,
        drain_seconds=drain, peak_client_inflight=samples["peak_active"],
        workers_with_requests=sum(bool(w["statuses"]) for w in workers),
        completed_in_window=sum(w["completed_in_window"] for w in workers) if duration else None,
        successful_in_window=successes if duration else None,
        successful_window_rps=successes / duration if duration else None)
    if rate:
        execution["scheduling"] = dict(
            pattern="uniform", rate_unit="iterations_per_second", target_rate=rate,
            scheduled=samples["scheduled"], started=sum(statuses.values()),
            dropped_capacity=samples["dropped_capacity"], dropped_late=samples["dropped_late"],
            admission_elapsed_seconds=samples["admission_elapsed"],
            started_in_admission_window=samples["started_in_window"],
            actual_start_rate=samples["started_in_window"] / samples["admission_elapsed"],
            scheduling_delays_ms=list(samples["delays"]), max_inflight_iterations=samples["concurrency"],
            overload_policy="drop_no_catchup")
    return measurement, execution


def _render(template_name, context):
    environment = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        undefined=StrictUndefined,
        # Dynamic JSON uses tojson, which remains valid with autoescaping.
        autoescape=True)
    return json.loads(environment.get_template(template_name).render(**context))


# gRFC A66 latency bounds converted from seconds to milliseconds. The final
# bucket_count element is the implicit (100000 ms, +Inf) bucket.
GRPC_A66_LATENCY_MS_BOUNDS = tuple(_render("grpc_a66_latency_ms_bounds.json.j2", {}))


def _outcome_counts(statuses, response_errors=0):
    completed = sum(statuses.values())
    successful = statuses.get("OK", 0) - response_errors
    return dict(planned=completed, started=completed, completed=completed,
                successful=successful, failed=completed - successful, unfinished=0,
                attempts=completed, response_errors=response_errors)


def _percentile(ordered, percentage):
    if not ordered:
        return None
    rank = max(1, math.ceil(len(ordered) * percentage / 100.0))
    return ordered[rank - 1]


def _latency_histogram(values):
    """Aggregate successful logical-request milliseconds into fixed A66 buckets."""
    ordered = sorted(float(value) for value in values)
    if any(not math.isfinite(value) or value < 0 for value in ordered):
        raise ValueError("Latency samples must be finite nonnegative milliseconds")

    bucket_counts = [0] * (len(GRPC_A66_LATENCY_MS_BOUNDS) + 1)
    for value in ordered:
        bucket_counts[bisect_left(GRPC_A66_LATENCY_MS_BOUNDS, value)] += 1

    total = sum(ordered)
    return _render("latency.json.j2", {
        "samples": len(ordered),
        "total": total,
        "average": total / len(ordered) if ordered else None,
        "p50": _percentile(ordered, 50),
        "p95": _percentile(ordered, 95),
        "p99": _percentile(ordered, 99),
        "maximum": ordered[-1] if ordered else None,
        "bucket_counts": bucket_counts,
    })


def _metrics(statuses, response_errors, latencies, elapsed):
    """Derive counts once from recorded outcomes, rather than validate duplicate copies."""
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError("measurement_elapsed_seconds must be finite and positive")
    counts = _outcome_counts(statuses, response_errors)
    latency = _latency_histogram(latencies)
    if latency["samples"] != counts["successful"]:
        raise ValueError("Successful latency samples must match successful outcomes")
    exceeded = sum(value > 1000 for value in latencies)
    return {
        "count_unit": "rpc",
        "measurement_elapsed_seconds": elapsed,
        "counts": counts,
        "rates_per_second": {
            "completed": counts["completed"] / elapsed,
            "successful": counts["successful"] / elapsed,
        },
        "latency_ms": latency,
        "grpc_status_counts": dict(sorted(statuses.items())),
        "latency_requirement": {
            "limit_ms": 1000,
            "evaluated_successful_requests": len(latencies),
            "within_limit": len(latencies) - exceeded,
            "exceeded": exceeded,
            "passed": not exceeded and not counts["failed"],
        },
    }


def _resource_summary(values, suffix=""):
    ordered = sorted(values)
    field_suffix = "_{}".format(suffix) if suffix else ""
    return {
        "samples": len(ordered),
        "average{}".format(field_suffix): sum(ordered) / len(ordered) if ordered else None,
        "p95{}".format(field_suffix): _percentile(ordered, 95),
        "max{}".format(field_suffix): ordered[-1] if ordered else None,
    }


def _resource_metrics(resources):
    """Aggregate boundary resource samples from sonic-mgmt collection output."""
    dut_cpu = []
    dut_memory_mib = []
    for processes, memory in (sample for boundary in resources for sample in boundary["monit"]):
        dut_cpu.append(sum(float(process.get("cpu_percent") or 0.0) for process in processes))
        if memory.get("used") is not None:
            dut_memory_mib.append(float(memory["used"]) / 1024.0)

    container_cpu = []
    container_memory_mib = []
    container_limit_mib = []
    units = {"B": 1 / 1024.0 / 1024.0, "KiB": 1 / 1024.0, "MiB": 1.0, "GiB": 1024.0}
    for boundary in resources:
        match = re.fullmatch(
            r"([0-9.]+)%\s+([0-9.]+)(B|KiB|MiB|GiB)\s*/\s*([0-9.]+)(B|KiB|MiB|GiB)",
            boundary["container"]["raw"].strip())
        if match:
            container_cpu.append(float(match.group(1)))
            container_memory_mib.append(float(match.group(2)) * units[match.group(3)])
            container_limit_mib.append(float(match.group(4)) * units[match.group(5)])

    container_memory = _resource_summary(container_memory_mib, "used")
    container_memory.update({
        "limit": container_limit_mib[-1] if container_limit_mib else None,
        "start_used": container_memory_mib[0] if container_memory_mib else None,
        "peak_used": max(container_memory_mib) if container_memory_mib else None,
        "end_used": container_memory_mib[-1] if container_memory_mib else None,
    })
    return {
        "dut_cpu_percent": _resource_summary(dut_cpu),
        "dut_memory_mib": _resource_summary(dut_memory_mib, "used"),
        "gnmi_container_cpu_percent": _resource_summary(container_cpu),
        "gnmi_container_memory_mib": container_memory,
    }


def _build_report(result):
    """Render a single report; connection labels describe the executed setup."""
    measurement = result.measurement
    requests = {}
    for method, samples in measurement["rpc"].items():
        operation = _metrics(samples["statuses"], samples["response_errors"], samples["latencies"],
                             measurement["elapsed_seconds"])
        operation["latency_ms"]["sample_population"] = "successful_{}_calls".format(method)
        request_type, _, entries = method.partition(":")
        operation["request_type"] = request_type
        if entries:
            operation["entry_count"] = int(entries)
        requests[method] = operation
    execution = _execution_metrics(result)
    load = dict(iterations=sum(measurement["statuses"].values()), concurrency=execution["concurrency"],
                duration_seconds=execution["admission_seconds"] or 0,
                warmup_seconds=execution["warmup"]["admission_seconds"])
    if "scheduling" in execution:
        load["scheduled_iterations"] = execution["scheduling"]["scheduled"]
    report = _render("report.json.j2", {
        "cid": result.cid,
        "started_ts": measurement["started_ts"],
        "finished_ts": measurement["finished_ts"],
        "device": result.device,
        "marker": result.marker,
        "blaster": result.blaster,
        "profile": result.profile,
        "connection_type": result.connection_type,
        "load": load,
        "requests": requests,
        "execution": execution,
        "resources": _resource_metrics(result.resources),
    })
    if not result.resources:
        report["sampling"] = {"method": "none", "sample_positions": [], "measurement_window_sampled": False}
    return report


def _execution_metrics(result):
    execution = dict(result.execution)
    if "scheduling" in execution:
        scheduling = dict(execution["scheduling"])
        delays = scheduling.pop("scheduling_delays_ms")
        if (scheduling["scheduled"] != scheduling["started"] + scheduling["dropped_capacity"] +
                scheduling["dropped_late"] or scheduling["started"] != sum(result.measurement["statuses"].values())
                or len(delays) != scheduling["started"]):
            raise ValueError("Inconsistent open-loop scheduling counts")
        scheduling["start_delay_ms"] = _latency_histogram(delays)
        scheduling["start_delay_ms"]["sample_population"] = "started_iterations"
        execution["scheduling"] = scheduling
    return execution
