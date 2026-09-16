"""Operation-level JSON helpers for SONiC gNMI client benchmarks."""

import json
import math
import os
import re
from bisect import bisect_left
from datetime import datetime, timezone

from tests.gnmi_benchmark.helpers import render_json_template

OPERATIONS = ("get", "set", "get-set", "scenario")

# gRFC A66 latency bounds converted from seconds to milliseconds. The final
# bucket_count element is the implicit (100000 ms, +Inf) bucket.
GRPC_A66_LATENCY_MS_BOUNDS = tuple(render_json_template("grpc_a66_latency_ms_bounds.json.j2", {}))


def _percentile(ordered, percentage):
    if not ordered:
        return None
    rank = max(1, math.ceil(len(ordered) * percentage / 100.0))
    return ordered[rank - 1]


def _parse_timestamp(value, name):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("{} must be an RFC 3339 timestamp".format(name)) from error
    else:
        raise ValueError("{} must be a datetime or RFC 3339 string".format(name))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("{} must be timezone-aware".format(name))
    return parsed


def _cell_timestamps(started_ts, finished_ts):
    started = _parse_timestamp(started_ts, "started_ts")
    finished = _parse_timestamp(finished_ts, "finished_ts")
    if finished < started:
        raise ValueError("finished_ts must not precede started_ts")
    return (
        started.astimezone(timezone.utc).isoformat(),
        finished.astimezone(timezone.utc).isoformat(),
    )


def _counts(mapping, names, label):
    missing = [name for name in names if name not in mapping]
    if missing:
        raise ValueError("{} is missing {}".format(label, ", ".join(missing)))
    values = {name: mapping[name] for name in names}
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values.values()):
        raise ValueError("{} must contain integer values".format(label))
    if any(value < 0 for value in values.values()):
        raise ValueError("{} must be nonnegative".format(label))
    return values


def grpc_a66_latency_histogram(values):
    """Aggregate successful logical-request milliseconds into fixed A66 buckets."""
    ordered = sorted(float(value) for value in values)
    if any(not math.isfinite(value) or value < 0 for value in ordered):
        raise ValueError("Latency samples must be finite nonnegative milliseconds")

    bucket_counts = [0] * (len(GRPC_A66_LATENCY_MS_BOUNDS) + 1)
    for value in ordered:
        bucket_counts[bisect_left(GRPC_A66_LATENCY_MS_BOUNDS, value)] += 1

    total = sum(ordered)
    return render_json_template("latency.json.j2", {
        "samples": len(ordered),
        "total": total,
        "average": total / len(ordered) if ordered else None,
        "p50": _percentile(ordered, 50),
        "p95": _percentile(ordered, 95),
        "p99": _percentile(ordered, 99),
        "maximum": ordered[-1] if ordered else None,
        "bucket_counts": bucket_counts,
    })


def build_operation_metrics(load, counts, successful_latencies_ms,
                            grpc_status_counts, measurement_elapsed_seconds, allow_idle_workers=False):
    """Validate RPC outcomes and compute metrics for one closed workload."""
    elapsed = float(measurement_elapsed_seconds)
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError("measurement_elapsed_seconds must be finite and positive")

    count_names = (
        "planned", "started", "completed", "successful", "failed",
        "unfinished", "attempts",
    )
    normalized_counts = _counts(counts, count_names, "Operation counts")
    response_errors = _counts({"response_errors": counts.get("response_errors", 0)},
                              ("response_errors",), "Response errors")["response_errors"]
    normalized_counts["response_errors"] = response_errors
    if normalized_counts["planned"] != normalized_counts["started"]:
        raise ValueError("planned must equal started")
    if normalized_counts["completed"] + normalized_counts["unfinished"] != normalized_counts["started"]:
        raise ValueError("completed + unfinished must equal started")
    if normalized_counts["successful"] + normalized_counts["failed"] != normalized_counts["completed"]:
        raise ValueError("successful + failed must equal completed")
    if normalized_counts["attempts"] < normalized_counts["started"]:
        raise ValueError("attempts must not be less than started")

    load_names = ("logical_requests", "concurrency")
    normalized_load = _counts(load, load_names, "Load")
    if normalized_load["logical_requests"] != normalized_counts["planned"]:
        raise ValueError("load logical_requests must equal planned")
    if normalized_load["concurrency"] <= 0:
        raise ValueError("load concurrency must be positive")
    if (not allow_idle_workers and not load.get("duration_seconds")
            and normalized_load["concurrency"] > normalized_load["logical_requests"]):
        raise ValueError("load concurrency must not exceed logical_requests")

    latency = grpc_a66_latency_histogram(successful_latencies_ms)
    if latency["samples"] != normalized_counts["successful"]:
        raise ValueError("Successful latency samples must equal successful logical requests")

    normalized_statuses = _counts(
        grpc_status_counts, tuple(grpc_status_counts), "gRPC status counts"
    )
    if sum(normalized_statuses.values()) != normalized_counts["completed"]:
        raise ValueError("gRPC status counts must equal completed logical requests")
    if normalized_statuses.get("OK", 0) != normalized_counts["successful"] + response_errors:
        raise ValueError("gRPC OK status count must equal successful logical requests")
    if sum(
        count for name, count in normalized_statuses.items() if name != "OK"
    ) + response_errors != normalized_counts["failed"]:
        raise ValueError("Non-OK gRPC status counts must equal failed logical requests")

    return {
        "measurement_elapsed_seconds": elapsed,
        "counts": normalized_counts,
        "rates_per_second": {
            "completed": normalized_counts["completed"] / elapsed,
            "successful": normalized_counts["successful"] / elapsed,
        },
        "latency_ms": latency,
        "grpc_status_counts": dict(sorted(normalized_statuses.items())),
    }


def write_benchmark_report(output_dir, report):
    """Write the operation and resource metrics together in one JSON file."""
    cid = report["cid"]
    if not cid or not re.fullmatch(r"[A-Za-z0-9._-]+", str(cid)):
        raise ValueError("cid must be a nonempty filesystem-safe identifier")
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "{}-report.json".format(cid))
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    return path


def _resource_summary(values, suffix=""):
    ordered = sorted(values)
    field_suffix = "_{}".format(suffix) if suffix else ""
    return {
        "samples": len(ordered),
        "average{}".format(field_suffix): sum(ordered) / len(ordered) if ordered else None,
        "p95{}".format(field_suffix): _percentile(ordered, 95),
        "max{}".format(field_suffix): ordered[-1] if ordered else None,
    }


def _memory_to_mib(value, unit):
    return float(value) * {
        "B": 1 / 1024.0 / 1024.0,
        "KiB": 1 / 1024.0,
        "MiB": 1.0,
        "GiB": 1024.0,
    }[unit]


def parse_container_resource_sample(sample):
    """Normalize the existing benchmark docker-stats sample into MiB values."""
    if any(name in sample for name in ("cpu_percent", "memory_used_mib", "memory_limit_mib")):
        return sample
    match = re.fullmatch(
        r"([0-9.]+)%\s+([0-9.]+)(B|KiB|MiB|GiB)\s*/\s*([0-9.]+)(B|KiB|MiB|GiB)",
        sample.get("raw", "").strip(),
    )
    if not match:
        return {}
    return {
        "cpu_percent": float(match.group(1)),
        "memory_used_mib": _memory_to_mib(match.group(2), match.group(3)),
        "memory_limit_mib": _memory_to_mib(match.group(4), match.group(5)),
    }


def build_resource_metrics(monit_results, container_samples):
    """Aggregate boundary resource samples from sonic-mgmt collection output."""
    dut_cpu = []
    dut_memory_mib = []
    for processes, memory in monit_results or []:
        dut_cpu.append(sum(float(process.get("cpu_percent") or 0.0) for process in processes))
        if memory.get("used") is not None:
            dut_memory_mib.append(float(memory["used"]) / 1024.0)

    container_cpu = []
    container_memory_mib = []
    container_limit_mib = []
    for raw_sample in container_samples or []:
        sample = parse_container_resource_sample(raw_sample)
        if sample.get("cpu_percent") is not None:
            container_cpu.append(float(sample["cpu_percent"]))
        if sample.get("memory_used_mib") is not None:
            container_memory_mib.append(float(sample["memory_used_mib"]))
        if sample.get("memory_limit_mib") is not None:
            container_limit_mib.append(float(sample["memory_limit_mib"]))

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


def build_benchmark_report(cid, client, operation, connection_type, auth_mode,
                           device, load, result, monit_results, container_samples):
    """Render a single report; connection labels describe the executed setup."""
    if operation not in OPERATIONS:
        raise ValueError("Unsupported benchmark operation: {}".format(operation))
    if connection_type not in ("TLS", "UDS") or auth_mode not in ("normal", "bypass"):
        raise ValueError("Unsupported connection_type or auth_mode")
    if not cid or not re.fullmatch(r"[A-Za-z0-9._-]+", str(cid)):
        raise ValueError("cid must be a nonempty filesystem-safe identifier")
    measurement = result["measurement"]
    started_ts, finished_ts = _cell_timestamps(measurement["started_ts"], measurement["finished_ts"])
    metrics = build_operation_metrics(
        load, result["counts"], result["successful_latencies_ms"],
        result["grpc_status_counts"], measurement["elapsed_seconds"],
        allow_idle_workers=result.get("traffic_pattern") == "open-loop",
    )
    if operation in ("get-set", "scenario"):
        metrics["count_unit"] = "scenario_iteration" if operation == "scenario" else "get_set_workflow"
        metrics["workflow_status_counts"] = metrics.pop("grpc_status_counts")
        metrics["latency_ms"]["sample_population"] = (
            "successful_scenario_iterations" if operation == "scenario" else "successful_get_set_workflows")
        metrics["operations"] = {}
        for name in result["operations"]:
            raw = result["operations"][name]
            statuses = raw["grpc_status_counts"]
            completed = sum(statuses.values())
            successful = statuses.get("OK", 0) - raw["response_errors"]
            rpc_counts = dict(planned=completed, started=completed, completed=completed,
                              successful=successful, failed=completed - successful, unfinished=0,
                              attempts=completed, response_errors=raw["response_errors"])
            # Some workflows skip Set after Get failure; there may be zero Set calls.
            rpc_load = dict(logical_requests=completed, concurrency=load["concurrency"])
            metrics["operations"][name] = build_operation_metrics(
                rpc_load, rpc_counts, raw["successful_latencies_ms"], statuses, measurement["elapsed_seconds"],
                allow_idle_workers=True)
            if operation == "scenario":
                metrics["operations"][name]["method"] = raw["method"]
                metrics["operations"][name]["skipped"] = result["counts"]["started"] - completed
        if operation == "get-set":
            metrics["set_skipped_after_get_failure"] = (
                metrics["operations"]["get"]["counts"]["completed"] -
                metrics["operations"]["set"]["counts"]["completed"])
    execution = dict(result.get("execution", {}))
    if "scheduling" in execution:
        scheduling = dict(execution["scheduling"])
        delays = scheduling.pop("scheduling_delays_ms")
        scheduling["start_delay_ms"] = grpc_a66_latency_histogram(delays)
        scheduling["start_delay_ms"]["sample_population"] = "started_iterations"
        if (scheduling["scheduled"] != scheduling["started"] + scheduling["dropped_capacity"] +
                scheduling["dropped_late"] or scheduling["started"] != result["counts"]["started"]
                or len(delays) != scheduling["started"]):
            raise ValueError("Inconsistent open-loop scheduling counts")
        execution["scheduling"] = scheduling
    report = render_json_template("report.json.j2", {
        "cid": str(cid),
        "started_ts": started_ts,
        "finished_ts": finished_ts,
        "device": dict(device),
        "client": client,
        "operation": operation,
        "bypass_requested": result.get("bypass_requested", False),
        "backend_path": result.get("backend_path", "unverified"),
        "backend_evidence": result.get("backend_evidence", {}),
        "payload_profile": result.get("payload_profile", "single_port_description_v1" if operation == "set"
                                      else "empty_request_v1"),
        "connection_type": connection_type,
        "auth_mode": auth_mode,
        "load": dict(load),
        "metrics": metrics,
        "execution": execution,
        "connection_setup": result.get("connection_setup", "included_in_first_rpc"),
        "resources": build_resource_metrics(monit_results, container_samples),
    })
    if result.get("traffic_pattern") == "open-loop" or operation == "scenario":
        report["schema_version"] = 5
        report["benchmark"]["workload_model"] = (
            "open" if result.get("traffic_pattern") == "open-loop" else "closed")
        if operation == "scenario":
            report["benchmark"]["scenario"] = result["scenario"]
            report["benchmark"]["latency_measurement"]["boundary"] = "scenario_iteration"
            report["benchmark"]["latency_measurement"]["end"] = "last_step_return_or_first_error"
            report["benchmark"]["latency_measurement"]["excludes_response_error_inspection"] = False
            report["benchmark"]["latency_measurement"]["inspection_scope"] = (
                "intermediate_step_checks_included_final_step_check_excluded")
            report["benchmark"]["response_validation"] = "per_step_grpc_status_and_set_response_errors"
            report["benchmark"]["rpc_timeout_scope"] = "per_step"
            report["benchmark"]["rpc_latency_boundary"] = "stub_call_to_return_or_error"
    return report
