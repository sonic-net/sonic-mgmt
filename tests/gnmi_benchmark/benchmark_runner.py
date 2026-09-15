"""Count- or duration-limited grpcio load with isolated warmup/measurement phases.

Uses standard Executor ownership and Future result collection:
https://docs.python.org/3/library/concurrent.futures.html
"""

import json
import logging
import math
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import grpc
from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc

from tests.gnmi_benchmark.helpers import render_json_template

CLIENT_NAME = "grpcio"
logger = logging.getLogger(__name__)


def prepare_runner(_output_dir=None):
    """Retain the stateless runner interface used by the test harness."""
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
    return grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )


def _status(error):
    code = error.code()
    return code.name if code is not None else "UNKNOWN"


def _set_response_has_error(response):
    """Inspect explicit legacy Error codes after timing, not payload semantics."""
    return response.message.code != 0 or any(item.message.code != 0 for item in response.response)


def _build_request(operation, workload):
    if operation == "get":
        return gnmi_pb2.GetRequest()
    request = gnmi_pb2.SetRequest()
    update = request.update.add()
    update.path.origin = "sonic-db"
    path = (("CONFIG_DB", workload["instance"], "VNET_ROUTE_TUNNEL") if "payload" in workload else
            ("CONFIG_DB", workload["instance"], "PORT", workload["port"], "description"))
    for name in path:
        update.path.elem.add(name=name)
    update.val.json_ietf_val = (
        json.dumps(workload["payload"], sort_keys=True, separators=(",", ":")).encode()
        if "payload" in workload else b'"gnmi-benchmark"'
    )
    return request


@dataclass
class RpcResults:
    statuses: Counter = field(default_factory=Counter)
    latencies: list = field(default_factory=list)
    response_errors: int = 0


@dataclass
class WorkerResult:
    """Owned by one worker; collected through its Future after it finishes."""

    started_ts: datetime
    started_ns: int
    finished_ts: Optional[datetime] = None
    finished_ns: int = 0
    statuses: Counter = field(default_factory=Counter)
    latencies: list = field(default_factory=list)
    response_errors: int = 0
    completed_in_window: int = 0
    successful_in_window: int = 0
    operations: dict = field(default_factory=lambda: {name: RpcResults() for name in ("get", "set")})


class BenchmarkPhase:
    """One admission window, barrier and in-flight counter; never reused across phases."""

    def __init__(self, concurrency, duration_seconds):
        self.duration_seconds = duration_seconds
        self.start_ns = 0
        self.start_ts = None
        self.end_ns = 0
        self.active = 0
        self.peak_active = 0
        self.lock = threading.Lock()
        self.ready = threading.Barrier(concurrency, action=self._start_window)
        self.workers = []

    def _start_window(self):
        self.start_ns = time.perf_counter_ns()
        self.start_ts = datetime.now(timezone.utc)
        self.end_ns = self.start_ns + int(self.duration_seconds * 1_000_000_000)

    def run(self, executor, worker, counts):
        futures = [executor.submit(worker, self, count) for count in counts]
        self.workers = [future.result() for future in futures]
        return self

    @property
    def elapsed_seconds(self):
        start = self.start_ns if self.duration_seconds else min(w.started_ns for w in self.workers)
        return (max(w.finished_ns for w in self.workers) - start) / 1_000_000_000

    @property
    def drain_seconds(self):
        return max(0, self.elapsed_seconds - self.duration_seconds) if self.duration_seconds else 0

    @property
    def statuses(self):
        statuses = Counter()
        for worker in self.workers:
            statuses.update(worker.statuses)
        return statuses

    @property
    def response_errors(self):
        return sum(w.response_errors for w in self.workers)


class BenchmarkRunner:
    """Own the shared request/channel lifecycle and execute the two load phases."""

    def __init__(self, operation, concurrency, logical_requests, timeout_seconds,
                 workload=None, bypass_requested=False, duration_seconds=0, warmup_seconds=0):
        if operation not in ("get", "set", "get-set"):
            raise ValueError("Unsupported benchmark operation: {}".format(operation))
        if bypass_requested and operation not in ("set", "get-set"):
            raise ValueError("Validation bypass is only supported for Set")
        if any(not math.isfinite(v) or v < 0 for v in (duration_seconds, warmup_seconds)):
            raise ValueError("Duration and warmup must be finite nonnegative seconds")
        self.operation = operation
        self.concurrency = concurrency
        self.logical_requests = logical_requests
        self.timeout_seconds = timeout_seconds
        self.duration_seconds = duration_seconds
        self.warmup_seconds = warmup_seconds
        self.bypass_requested = bypass_requested
        self.workload = workload
        self.request = _build_request(operation, workload)
        self.get_request = gnmi_pb2.GetRequest() if operation == "get-set" else None
        self.counts = _request_counts(logical_requests, concurrency)
        self.metadata = (("x-sonic-ss-bypass-validation", "true"),) if bypass_requested else ()
        self.stub = None

    def run(self, fixture, start_hook=None):
        channel = grpc.secure_channel(format_target(fixture.host, fixture.port), _read_credentials(fixture),
                                      options=(("grpc.enable_retries", 0),))
        try:
            self.stub = gnmi_pb2_grpc.gNMIStub(channel)
            connection_ready_seconds = self._await_readiness(channel)
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                warmup = self._run_warmup(executor)
                if start_hook is not None:
                    start_hook()
                measured = self._run_phase(executor, self.duration_seconds)
        finally:
            channel.close()
        return self._result(measured, warmup, connection_ready_seconds)

    def _await_readiness(self, channel):
        if not self.warmup_seconds:
            return None
        started = time.perf_counter_ns()
        grpc.channel_ready_future(channel).result(timeout=self.timeout_seconds)
        return (time.perf_counter_ns() - started) / 1_000_000_000

    def _run_phase(self, executor, duration):
        return BenchmarkPhase(self.concurrency, duration).run(executor, self._worker, self.counts)

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
        if self.operation == "get-set":
            summary["count_unit"] = "get_set_workflow"
            summary["workflow_status_counts"] = summary.pop("grpc_status_counts")
        logger.info("GNMI_BENCHMARK_WARMUP_JSON %s", json.dumps(summary, sort_keys=True))
        if not statuses.get("OK") or any(k != "OK" for k in statuses) or phase.response_errors:
            raise RuntimeError("Warmup failed; measured phase not started: {}".format(summary))
        return summary

    def _worker(self, phase, count):
        phase.ready.wait(timeout=self.timeout_seconds)
        result = WorkerResult(datetime.now(timezone.utc), time.perf_counter_ns())
        sent = 0
        while True:
            rpc_started = time.perf_counter_ns()
            if phase.duration_seconds:
                if rpc_started >= phase.end_ns:
                    break
            elif sent >= count:
                break
            sent += 1
            with phase.lock:
                phase.active += 1
                phase.peak_active = max(phase.peak_active, phase.active)
            ok = False
            try:
                if self.operation == "get-set":
                    ok, status, rpc_finished = self._combined_call(result)
                    result.statuses[status] += 1
                    if ok:
                        result.latencies.append((rpc_finished - rpc_started) / 1_000_000)
                    elif status == "OK":
                        result.response_errors += 1
                elif self.operation == "get":
                    response = self.stub.Get(self.request, timeout=self.timeout_seconds)
                else:
                    response = self.stub.Set(self.request, timeout=self.timeout_seconds, metadata=self.metadata)
                if self.operation != "get-set":
                    rpc_finished = time.perf_counter_ns()
                    elapsed_ms = (rpc_finished - rpc_started) / 1_000_000
                    result.statuses["OK"] += 1
                    # Preserve the timer boundary before explicit response inspection.
                    ok = self.operation != "set" or not _set_response_has_error(response)
                    if ok:
                        result.latencies.append(elapsed_ms)
                    else:
                        result.response_errors += 1
            except grpc.RpcError as error:
                rpc_finished = time.perf_counter_ns()
                result.statuses[_status(error)] += 1
            finally:
                with phase.lock:
                    phase.active -= 1
            if phase.duration_seconds and rpc_finished <= phase.end_ns:
                result.completed_in_window += 1
                result.successful_in_window += int(ok)
        result.finished_ns = time.perf_counter_ns()
        result.finished_ts = datetime.now(timezone.utc)
        return result

    def _combined_call(self, result):
        """Get success admits Set; each RPC has its own timer and deadline."""
        for operation in ("get", "set"):
            stats = result.operations[operation]
            started = time.perf_counter_ns()
            try:
                if operation == "get":
                    response = self.stub.Get(self.get_request, timeout=self.timeout_seconds)
                else:
                    response = self.stub.Set(self.request, timeout=self.timeout_seconds, metadata=self.metadata)
                finished = time.perf_counter_ns()
            except grpc.RpcError as error:
                finished = time.perf_counter_ns()
                status = _status(error)
                stats.statuses[status] += 1
                return False, status, finished
            stats.statuses["OK"] += 1
            if operation == "set" and _set_response_has_error(response):
                stats.response_errors += 1
                return False, "OK", finished
            stats.latencies.append((finished - started) / 1_000_000)
        return True, "OK", finished

    def _result(self, phase, warmup, connection_ready_seconds):
        statuses = phase.statuses
        completed = sum(statuses.values())
        if not self.duration_seconds and completed != self.logical_requests:
            raise RuntimeError("Python generator completed {} of {} requests".format(completed, self.logical_requests))
        successful = statuses.get("OK", 0) - phase.response_errors
        window_successes = sum(w.successful_in_window for w in phase.workers)
        started = phase.start_ts if self.duration_seconds else min(w.started_ts for w in phase.workers)
        finished = max(w.finished_ts for w in phase.workers)
        result = render_json_template("runner_result.json.j2", {
            "operation": self.operation, "batch_payload": bool(self.workload and "payload" in self.workload),
            "bypass_requested": self.bypass_requested, "duration_seconds": self.duration_seconds,
            "warmup_seconds": self.warmup_seconds, "warmup": warmup,
            "connection_ready_seconds": connection_ready_seconds, "completed": completed,
            "successful": successful, "response_errors": phase.response_errors,
            "total": completed if self.duration_seconds else self.logical_requests,
            "failed": completed - successful,
            "unfinished": 0 if self.duration_seconds else self.logical_requests - completed,
            "statuses": dict(sorted(statuses.items())), "started_ts": started.isoformat(),
            "finished_ts": finished.isoformat(), "elapsed_seconds": phase.elapsed_seconds,
            "drain_seconds": phase.drain_seconds, "peak_active": phase.peak_active,
            "workers_with_requests": sum(bool(w.statuses) for w in phase.workers),
            "completed_in_window": sum(w.completed_in_window for w in phase.workers),
            "successful_in_window": window_successes,
            "successful_window_rps": window_successes / self.duration_seconds if self.duration_seconds else None,
        })
        # Raw samples are in-memory input to statistics, not another published report.
        result["successful_latencies_ms"] = [v for w in phase.workers for v in w.latencies]
        if self.operation == "get-set":
            result["operations"] = {}
            for operation in ("get", "set"):
                stats = [w.operations[operation] for w in phase.workers]
                statuses = Counter()
                for item in stats:
                    statuses.update(item.statuses)
                result["operations"][operation] = {
                    "grpc_status_counts": dict(statuses),
                    "response_errors": sum(item.response_errors for item in stats),
                    "successful_latencies_ms": [v for item in stats for v in item.latencies],
                }
        return result


def run_benchmark(_state, fixture, operation, _output_dir, concurrency, logical_requests, timeout_seconds,
                  start_hook=None, workload=None, bypass_requested=False, duration_seconds=0, warmup_seconds=0):
    """Compatibility entry point for the pytest harness."""
    runner = BenchmarkRunner(operation, concurrency, logical_requests, timeout_seconds,
                             workload, bypass_requested, duration_seconds, warmup_seconds)
    return runner.run(fixture, start_hook)
