"""Coordinate phases, request execution and metrics independently of traffic policy."""

import json
import logging
import math
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import grpc
from pygnmi.spec.v080 import gnmi_pb2_grpc

from tests.gnmi_benchmark.helpers import render_json_template
from tests.gnmi_benchmark.scenarios import RpcExecutor, builtin_steps, set_response_has_error
from tests.gnmi_benchmark.traffic import ClosedLoop, UniformOpenLoop

CLIENT_NAME = "grpcio"
logger = logging.getLogger(__name__)
_set_response_has_error = set_response_has_error


def prepare_runner(_output_dir=None):
    return None


def format_target(host, port):
    if ":" in host and not host.startswith("["):
        host = "[{}]".format(host)
    return "{}:{}".format(host, port)


def _request_counts(logical_requests, concurrency):
    base, remainder = divmod(logical_requests, concurrency)
    return [base + (worker < remainder) for worker in range(concurrency)]


def _read_credentials(fixture):
    certs = fixture.pygnmi_client
    with open(certs.ca_cert, "rb") as stream:
        root_certificates = stream.read()
    with open(certs.client_key, "rb") as stream:
        private_key = stream.read()
    with open(certs.client_cert, "rb") as stream:
        certificate_chain = stream.read()
    return grpc.ssl_channel_credentials(root_certificates=root_certificates,
                                        private_key=private_key, certificate_chain=certificate_chain)


@dataclass
class RpcResults:
    statuses: Counter = field(default_factory=Counter)
    latencies: list = field(default_factory=list)
    response_errors: int = 0


@dataclass
class WorkerResult:
    started_ts: datetime
    started_ns: int
    finished_ts: Optional[datetime] = None
    finished_ns: int = 0
    statuses: Counter = field(default_factory=Counter)
    latencies: list = field(default_factory=list)
    response_errors: int = 0
    completed_in_window: int = 0
    successful_in_window: int = 0
    operations: dict = field(default_factory=dict)


class BenchmarkRunner:
    def __init__(self, operation, concurrency, logical_requests, timeout_seconds,
                 workload=None, bypass_requested=False, duration_seconds=0, warmup_seconds=0,
                 traffic_pattern="closed-loop", rate=0):
        if operation not in ("get", "set", "get-set", "scenario"):
            raise ValueError("Unsupported benchmark operation: {}".format(operation))
        if bypass_requested and operation not in ("set", "get-set"):
            raise ValueError("Validation bypass is only supported for built-in Set workloads")
        if any(not math.isfinite(v) or v < 0 for v in (duration_seconds, warmup_seconds)):
            raise ValueError("Duration and warmup must be finite nonnegative seconds")
        if not 1 <= concurrency <= 500 or not 1 <= logical_requests <= 1_000_000 or timeout_seconds <= 0:
            raise ValueError("Invalid concurrency, request count or timeout")
        if traffic_pattern not in ("closed-loop", "open-loop"):
            raise ValueError("Unknown traffic pattern")
        if not math.isfinite(rate) or (traffic_pattern == "open-loop" and not 0 < rate <= 1_000_000):
            raise ValueError("Open-loop rate must be finite and in (0, 1000000]")
        if traffic_pattern == "closed-loop" and rate:
            raise ValueError("Rate is only supported for open-loop")
        self.operation = operation
        self.concurrency = concurrency
        self.logical_requests = logical_requests
        self.timeout_seconds = timeout_seconds
        self.duration_seconds = duration_seconds
        self.warmup_seconds = warmup_seconds
        self.bypass_requested = bypass_requested
        self.workload = workload
        self.traffic_pattern = traffic_pattern
        self.rate = rate
        self.steps = workload["steps"] if operation == "scenario" else builtin_steps(
            operation, workload, bypass_requested)
        self.counts = _request_counts(logical_requests, concurrency)
        self.rpc = None

    def run(self, fixture, start_hook=None):
        channel = grpc.secure_channel(format_target(fixture.host, fixture.port), _read_credentials(fixture),
                                      options=(("grpc.enable_retries", 0),))
        try:
            stub = gnmi_pb2_grpc.gNMIStub(channel)
            self.rpc = RpcExecutor(stub, self.steps, self.timeout_seconds, _set_response_has_error)
            connection_ready_seconds = None
            if self.warmup_seconds or self.rate:
                started = time.perf_counter_ns()
                grpc.channel_ready_future(channel).result(timeout=self.timeout_seconds)
                connection_ready_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                warmup = self._run_warmup(executor)
                if start_hook is not None:
                    start_hook()
                measured = self._run_phase(executor, self.duration_seconds)
        finally:
            channel.close()
        return self._result(measured, warmup, connection_ready_seconds)

    def _new_result(self):
        return WorkerResult(datetime.now(timezone.utc), time.perf_counter_ns(),
                            operations={s.name: RpcResults() for s in self.steps})

    def _run_phase(self, executor, duration):
        policy = UniformOpenLoop if self.rate else ClosedLoop
        return policy(self.concurrency, duration, self.timeout_seconds, self.rate).run(
            executor, self._execute, self._new_result, self.counts)

    def _run_warmup(self, executor):
        summary = dict(admission_seconds=self.warmup_seconds, elapsed_seconds=0, drain_seconds=0,
                       grpc_status_counts={}, completed=0)
        if not self.warmup_seconds:
            return summary
        phase = self._run_phase(executor, self.warmup_seconds)
        statuses = phase.statuses
        summary.update(elapsed_seconds=phase.elapsed_seconds, drain_seconds=phase.drain_seconds,
                       grpc_status_counts=dict(statuses), response_errors=phase.response_errors,
                       completed=sum(statuses.values()))
        if self.operation in ("get-set", "scenario"):
            summary["count_unit"] = "scenario_iteration" if self.operation == "scenario" else "get_set_workflow"
            summary["workflow_status_counts"] = summary.pop("grpc_status_counts")
        if self.rate:
            summary["scheduled"] = phase.scheduled
            summary["dropped"] = phase.dropped_late + phase.dropped_capacity
        logger.info("GNMI_BENCHMARK_WARMUP_JSON %s", json.dumps(summary, sort_keys=True))
        if (not statuses.get("OK") or any(k != "OK" for k in statuses) or phase.response_errors
                or summary.get("dropped", 0)):
            raise RuntimeError("Warmup failed; measured phase not started: {}".format(summary))
        return summary

    def _execute(self, phase, result, index, started):
        ok, status, finished = self.rpc.execute(result.operations, index)
        result.statuses[status] += 1
        if ok:
            result.latencies.append((finished - started) / 1_000_000)
        elif status == "OK":
            result.response_errors += 1
        if phase.duration_seconds and finished <= phase.end_ns:
            result.completed_in_window += 1
            result.successful_in_window += int(ok)

    def _result(self, phase, warmup, connection_ready_seconds):
        statuses = phase.statuses
        completed = sum(statuses.values())
        if not self.rate and not self.duration_seconds and completed != self.logical_requests:
            raise RuntimeError("Python generator completed {} of {} requests".format(completed, self.logical_requests))
        successful = statuses.get("OK", 0) - phase.response_errors
        window_successes = sum(w.successful_in_window for w in phase.workers)
        started = phase.start_ts if self.duration_seconds or self.rate else min(w.started_ts for w in phase.workers)
        finished = max((w.finished_ts for w in phase.workers), default=started)
        result = render_json_template("runner_result.json.j2", {
            "operation": self.operation, "batch_payload": bool(self.workload and "payload" in self.workload),
            "bypass_requested": self.bypass_requested, "duration_seconds": self.duration_seconds,
            "warmup_seconds": self.warmup_seconds, "warmup": warmup,
            "connection_ready_seconds": connection_ready_seconds, "completed": completed,
            "successful": successful, "response_errors": phase.response_errors,
            "total": completed if self.duration_seconds or self.rate else self.logical_requests,
            "failed": completed - successful, "unfinished": 0,
            "statuses": dict(sorted(statuses.items())), "started_ts": started.isoformat(),
            "finished_ts": finished.isoformat(), "elapsed_seconds": phase.elapsed_seconds,
            "drain_seconds": phase.drain_seconds, "peak_active": phase.peak_active,
            "workers_with_requests": sum(bool(w.statuses) for w in phase.workers),
            "completed_in_window": sum(w.completed_in_window for w in phase.workers),
            "successful_in_window": window_successes,
            "successful_window_rps": window_successes / self.duration_seconds if self.duration_seconds else None,
        })
        result["successful_latencies_ms"] = [v for w in phase.workers for v in w.latencies]
        result["traffic_pattern"] = self.traffic_pattern
        if self.rate:
            result["connection_setup"] = "ready_before_load"
            result["measurement"]["finished_ts"] = phase.finished_ts.isoformat()
            result["execution"]["scheduling"] = {
                "pattern": "uniform", "rate_unit": "iterations_per_second", "target_rate": self.rate,
                "scheduled": phase.scheduled, "started": completed,
                "dropped_capacity": phase.dropped_capacity, "dropped_late": phase.dropped_late,
                "admission_elapsed_seconds": phase.admission_elapsed,
                "started_in_admission_window": phase.started_in_window,
                "actual_start_rate": phase.started_in_window / phase.admission_elapsed,
                "scheduling_delays_ms": phase.delays,
                "max_inflight_iterations": self.concurrency,
                "overload_policy": "drop_no_catchup",
            }
        if self.operation in ("get-set", "scenario"):
            result["operations"] = {}
            for step in self.steps:
                stats = [w.operations[step.name] for w in phase.workers]
                statuses = Counter()
                for item in stats:
                    statuses.update(item.statuses)
                result["operations"][step.name] = {
                    "grpc_status_counts": dict(statuses), "method": step.method,
                    "response_errors": sum(item.response_errors for item in stats),
                    "successful_latencies_ms": [v for item in stats for v in item.latencies],
                }
        if self.operation == "scenario":
            result["scenario"] = self.workload["scenario"]
            result["bypass_requested"] = any(
                step.method == "set" and dict(step.metadata).get("x-sonic-ss-bypass-validation") == "true"
                for step in self.steps)
            result["payload_profile"] = "configured_gnmi_scenario_v1"
            result["backend_path"] = "unverified"
        return result


def run_benchmark(_state, fixture, operation, _output_dir, concurrency, logical_requests, timeout_seconds,
                  start_hook=None, workload=None, bypass_requested=False, duration_seconds=0, warmup_seconds=0,
                  traffic_pattern="closed-loop", rate=0):
    runner = BenchmarkRunner(operation, concurrency, logical_requests, timeout_seconds,
                             workload, bypass_requested, duration_seconds, warmup_seconds, traffic_pattern, rate)
    return runner.run(fixture, start_hook)
