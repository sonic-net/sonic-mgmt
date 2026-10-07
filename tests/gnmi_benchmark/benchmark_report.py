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
        self.warmup = None
        self.load = {}
        self.resources = []

    def generate(self, *, samples, warmup, resources, marker, blaster, profile=None):
        """Derive report fields from raw phase data; never control test execution."""
        self.measurement = _phase_metrics(samples)
        self.warmup = _phase_metrics(warmup) if warmup is not None else None
        self.load = dict(concurrency=samples["concurrency"], duration_seconds=samples["duration_seconds"],
                         warmup_seconds=warmup["duration_seconds"] if warmup is not None else 0,
                         traffic_pattern="open-loop" if samples["rate"] else "closed-loop")
        if samples["rate"]:
            self.load["target_iterations_per_second"] = samples["rate"]
        self.resources = resources
        self.marker, self.blaster = marker, blaster
        self.profile = dict(profile or {})
        return self

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
    rpc = {}
    for worker in workers:
        for method, rpc_samples in worker["rpc"].items():
            if method not in rpc:
                rpc[method] = dict(statuses=Counter(), response_errors=0, latencies=[])
            rpc[method]["statuses"].update(rpc_samples["statuses"])
            rpc[method]["response_errors"] += rpc_samples["response_errors"]
            rpc[method]["latencies"].extend(rpc_samples["latencies"])
    measurement = dict(started_ts=start_ts.isoformat(), finished_ts=finished_ts.isoformat(),
                       elapsed_seconds=elapsed, rpc=rpc)
    if rate:
        measurement["dropped_iterations"] = samples["dropped_capacity"] + samples["dropped_late"]
    return measurement


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
    count = sum(statuses.values())
    return dict(count=count, error=count - statuses.get("OK", 0) + response_errors)


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


def _metrics(statuses, response_errors, latencies):
    """Derive counts once from recorded outcomes, rather than validate duplicate copies."""
    counts = _outcome_counts(statuses, response_errors)
    latency = _latency_histogram(latencies)
    return dict(counts, latency_ms=latency)


def _resource_summary(values, suffix=""):
    ordered = sorted(values)
    field_suffix = "_{}".format(suffix) if suffix else ""
    return {
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
    warmup = None
    if result.warmup is not None:
        warmup = {key: value for key, value in result.warmup.items() if key != "rpc"}
        warmup["requests"] = _requests(result.warmup, latency=False)
    profile = dict(result.profile)
    profile.pop("routes_per_request", None)  # entry_count lives with each RPC method.
    report = _render("report.json.j2", {
        "cid": result.cid,
        "started_ts": measurement["started_ts"],
        "finished_ts": measurement["finished_ts"],
        "device": result.device,
        "marker": result.marker,
        "blaster": result.blaster,
        "profile": profile,
        "connection_type": result.connection_type,
        "load": result.load,
        "requests": _requests(measurement),
        "warmup": warmup,
        "elapsed_seconds": measurement["elapsed_seconds"],
        "dropped_iterations": measurement.get("dropped_iterations"),
        "resources": _resource_metrics(result.resources),
    })
    return report


def _requests(phase, latency=True):
    requests = {}
    for method, samples in phase["rpc"].items():
        name, _, entries = method.partition(":")
        if name in requests:
            raise ValueError("One entry_count per RPC method is required")
        operation = (_metrics(samples["statuses"], samples["response_errors"], samples["latencies"])
                     if latency else _outcome_counts(samples["statuses"], samples["response_errors"]))
        if entries:
            operation["entry_count"] = int(entries)
        requests[name] = operation
    return requests
