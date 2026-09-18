"""Blaster owns traffic scheduling and RPC execution; Runner owns resource lifecycle."""

import math
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone

import grpc

from tests.gnmi_benchmark.helpers import BYPASS_METADATA, route_resources


@dataclass
class Blaster(ABC):
    concurrency: int = 4
    logical_requests: int = 100
    timeout_seconds: float = 120
    duration_seconds: float = 0
    warmup_seconds: float = 0
    traffic_pattern: str = "closed-loop"
    rate: float = 0
    marker: str = ""

    def __post_init__(self):
        if not self.marker:
            self.marker = self.name
        if any(not math.isfinite(v) or v < 0 for v in (self.duration_seconds, self.warmup_seconds)):
            raise ValueError("Duration and warmup must be finite nonnegative seconds")
        if (type(self.concurrency) is not int or not 1 <= self.concurrency <= 500 or
                type(self.logical_requests) is not int or not 1 <= self.logical_requests <= 1_000_000 or
                not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0):
            raise ValueError("Invalid concurrency, request count or timeout")
        if self.traffic_pattern not in ("closed-loop", "open-loop"):
            raise ValueError("Unknown traffic pattern")
        if not math.isfinite(self.rate) or (self.traffic_pattern == "open-loop" and not 0 < self.rate <= 1_000_000):
            raise ValueError("Open-loop rate must be finite and in (0, 1000000]")
        if self.traffic_pattern == "closed-loop" and self.rate:
            raise ValueError("Rate is only supported for open-loop")

    def resources(self, host, stub):
        return nullcontext(None)

    def profile(self):
        return {}

    @abstractmethod
    def workload(self, session, prepared):
        """Execute one logical iteration through session.get/set."""

    def blast(self, stub, prepared, duration=None):
        """Run one fully drained phase and return raw counters, timestamps and samples.

        Runner may pass warmup duration; otherwise use the configured measurement
        duration/count. Each phase owns its pool, counters and arrival clock.
        """
        duration = self.duration_seconds if duration is None else duration
        workers = self.concurrency if self.rate or self.duration_seconds else min(
            self.concurrency, self.logical_requests)

        def execute(phase, samples, index, started):
            session = _Session(stub, self.timeout_seconds, index, samples.rpc)
            try:
                self.workload(session, prepared)
            except _RpcFailed:
                pass
            if session.finished_ns is None:
                raise ValueError("workload must issue at least one RPC through the session")
            samples.statuses[session.status] += 1
            samples.response_errors += session.response_errors
            if duration and session.finished_ns <= phase.end_ns:
                samples.completed_in_window += 1
                samples.successful_in_window += int(not session.failed)

        base, remainder = divmod(self.logical_requests, workers)
        counts = [base + (worker < remainder) for worker in range(workers)]
        policy = OpenLoop if self.traffic_pattern == "open-loop" else ClosedLoop
        phase = policy(workers, duration, self.timeout_seconds, self.rate).run(execute, _Samples, counts)
        if (not self.rate and not duration
                and sum(sum(w.statuses.values()) for w in phase.workers) != self.logical_requests):
            raise RuntimeError("Generator did not complete the requested iteration count")
        return dict(
            workers=[dict(vars(w), statuses=dict(w.statuses)) for w in phase.workers],
            start_ns=phase.start_ns, start_ts=phase.start_ts, finished_ts=phase.finished_ts,
            duration_seconds=duration, rate=self.rate, concurrency=workers,
            peak_active=phase.peak_active, scheduled=phase.scheduled,
            dropped_capacity=phase.dropped_capacity, dropped_late=phase.dropped_late,
            admission_elapsed=phase.admission_elapsed, started_in_window=phase.started_in_window,
            delays=list(phase.delays))


@dataclass
class RouteTableBlaster(Blaster):
    """Round-robin VNET Get→Set, with all route batches preloaded using bypass."""

    name = "route-table"
    logical_requests: int = 1000
    route_distribution: dict = field(default_factory=lambda: {16000: 1, 20000: 12})
    routes_per_request: int = 20000

    def __post_init__(self):
        super().__post_init__()
        if not isinstance(self.route_distribution, dict) or not self.route_distribution:
            raise ValueError("route_distribution must map routes per VNET to VNET count")
        distribution = {}
        for routes, count in self.route_distribution.items():
            if isinstance(routes, str) and routes.isdecimal():
                routes = int(routes)
            if type(routes) is not int or not 1 <= routes <= 20000 or type(count) is not int or count < 1:
                raise ValueError("each distribution entry requires 1..20000 routes and a positive integer VNET count")
            if routes in distribution:
                raise ValueError("duplicate route count in distribution")
            distribution[routes] = count
        if sum(routes * count for routes, count in distribution.items()) > 256000:
            raise ValueError("total VNET_ROUTE_TUNNEL routes must not exceed 256000")
        self.route_distribution = dict(sorted(distribution.items()))
        largest = max(distribution)
        if (type(self.routes_per_request) is not int or not 1 <= self.routes_per_request <= largest or
                largest % self.routes_per_request):
            raise ValueError("routes_per_request must be a positive divisor of the largest VNET route count")

    def resources(self, host, stub):
        return route_resources(host, self.route_distribution, self.routes_per_request, stub, self.timeout_seconds)

    def profile(self):
        largest = max(self.route_distribution)
        measured_vnets = self.route_distribution[largest]
        measured_routes = largest * measured_vnets
        total = sum(routes * count for routes, count in self.route_distribution.items())
        return dict(route_distribution={str(routes): count for routes, count in self.route_distribution.items()},
                    vnet_count=sum(self.route_distribution.values()),
                    total_routes=total, routes_per_request=self.routes_per_request,
                    measured_vnet_count=measured_vnets, measured_routes=measured_routes,
                    background_routes=total - measured_routes,
                    platform_route_limit=256000, bypass_requested=True,
                    selection="largest_vnets_round_robin_then_disjoint_batches", preloaded=True)

    def workload(self, session, prepared):
        read, write = prepared[session.index % len(prepared)]
        entries = len(read.path)
        session.get(read, entry_count=entries)
        session.set(write, metadata=BYPASS_METADATA, entry_count=entries)


@dataclass
class _Samples:
    started_ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_ns: int = field(default_factory=lambda: time.perf_counter_ns())
    finished_ts: datetime = None
    finished_ns: int = 0
    statuses: Counter = field(default_factory=Counter)
    response_errors: int = 0
    completed_in_window: int = 0
    successful_in_window: int = 0
    rpc: dict = field(default_factory=dict)


class _RpcFailed(Exception):
    """Stop this iteration after an RPC error, without hiding unexpected Python errors."""


class _Session:
    """Time each RPC separately; iterations only control scheduling and fail-fast."""

    def __init__(self, stub, timeout, index, rpc):
        self.stub, self.timeout, self.index = stub, timeout, index
        self.rpc = rpc
        self.status = "OK"
        self.response_errors = 0
        self.finished_ns = None
        self.failed = False

    def get(self, request, metadata=(), entry_count=None):
        return self._call(self.stub.Get, request, metadata, False, entry_count)

    def set(self, request, metadata=(), entry_count=None):
        return self._call(self.stub.Set, request, metadata, True, entry_count)

    def _call(self, call, request, metadata, is_set, entry_count):
        if self.failed:
            raise _RpcFailed()
        kwargs = {"timeout": self.timeout}
        if metadata or is_set:
            kwargs["metadata"] = metadata
        method = "set" if is_set else "get"
        if entry_count is not None:
            method = "{}:{}".format(method, entry_count)
        if method not in self.rpc:
            self.rpc[method] = dict(statuses={}, response_errors=0, latencies=[])
        samples = self.rpc[method]
        started = time.perf_counter_ns()
        try:
            response = call(request, **kwargs)
            self.finished_ns = time.perf_counter_ns()
        except grpc.RpcError as error:
            self.finished_ns = time.perf_counter_ns()
            code = error.code()
            self.status = code.name if code is not None else "UNKNOWN"
            samples["statuses"][self.status] = samples["statuses"].get(self.status, 0) + 1
            self.failed = True
            raise _RpcFailed() from error
        samples["statuses"]["OK"] = samples["statuses"].get("OK", 0) + 1
        if is_set and (response.message.code != 0 or any(item.message.code != 0 for item in response.response)):
            samples["response_errors"] += 1
            self.response_errors = 1
            self.failed = True
            raise _RpcFailed()
        samples["latencies"].append((self.finished_ns - started) / 1_000_000)
        return response


class LoadLoop(ABC):
    """Shared phase state and execution lifecycle; subclasses supply only scheduling."""

    def __init__(self, concurrency, duration_seconds, timeout_seconds, rate=0):
        self.concurrency = concurrency
        self.duration_seconds = duration_seconds
        self.timeout_seconds = timeout_seconds
        self.rate = rate
        self.start_ns = self.end_ns = 0
        self.start_ts = None
        self.active = self.peak_active = 0
        self.lock = threading.Lock()
        self.workers = []
        self.scheduled = self.dropped_capacity = self.dropped_late = 0
        self.delays = []
        self.started_in_window = 0
        self.admission_elapsed = 0
        self.finished_ts = None

    def run(self, callback, result_factory, counts):
        """Own the worker pool and drain it on both normal and exceptional exits."""
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            self._schedule(executor, callback, result_factory, counts)
        return self

    @abstractmethod
    def _schedule(self, executor, callback, result_factory, counts):
        """Admit iterations using invoke(); collect the resulting worker samples."""

    def _start(self):
        self.start_ns = time.perf_counter_ns()
        self.start_ts = datetime.now(timezone.utc)
        self.end_ns = self.start_ns + int(self.duration_seconds * 1_000_000_000)

    def invoke(self, callback, result, index, scheduled_ns=None):
        started = time.perf_counter_ns()
        with self.lock:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            if scheduled_ns is not None:
                self.delays.append((started - scheduled_ns) / 1_000_000)
                if started < self.end_ns:
                    self.started_in_window += 1
        try:
            callback(self, result, index, started)
        finally:
            with self.lock:
                self.active -= 1
            result.finished_ns = time.perf_counter_ns()
            result.finished_ts = datetime.now(timezone.utc)


class ClosedLoop(LoadLoop):
    """Preserve fixed per-worker quotas in count mode; no pacing between calls."""

    def _schedule(self, executor, callback, result_factory, counts):
        barrier = threading.Barrier(self.concurrency, action=self._start)

        def worker(worker_id, count):
            barrier.wait(timeout=self.timeout_seconds)
            result = result_factory()
            sent = 0
            while True:
                if self.duration_seconds:
                    if time.perf_counter_ns() >= self.end_ns:
                        break
                elif sent >= count:
                    break
                self.invoke(callback, result, worker_id + sent * self.concurrency)
                sent += 1
            result.finished_ns = time.perf_counter_ns()
            result.finished_ts = datetime.now(timezone.utc)
            return result

        futures = [executor.submit(worker, index, count) for index, count in enumerate(counts)]
        self.workers = [future.result() for future in futures]


class OpenLoop(LoadLoop):
    """Fixed arrival clock with nonblocking admission and no catch-up bursts.

    At most concurrency tasks (queued plus executing) are admitted. A late clock
    skips expired slots; exhausted capacity drops the current slot, never waits
    for a response. Only drain waits for admitted operations to finish.
    """

    def _schedule(self, executor, callback, result_factory, counts):
        total = math.ceil(self.duration_seconds * self.rate) if self.duration_seconds else sum(counts)
        admission_seconds = self.duration_seconds or total / self.rate
        slots = threading.BoundedSemaphore(self.concurrency)
        local = threading.local()
        pending = set()
        barrier = threading.Barrier(self.concurrency + 1, action=self._start)
        startup = [executor.submit(barrier.wait, self.timeout_seconds) for _ in counts]
        barrier.wait(timeout=self.timeout_seconds)
        for future in startup:
            future.result()
        self.end_ns = self.start_ns + int(admission_seconds * 1_000_000_000)

        def check_errors():
            done = {f for f in pending if f.done()}
            for future in done:
                future.result()
            pending.difference_update(done)

        def wait_until(deadline):
            while time.perf_counter_ns() < deadline:
                check_errors()
                time.sleep(min(.05, max(0, (deadline - time.perf_counter_ns()) / 1_000_000_000)))

        def task(index, scheduled):
            try:
                if not hasattr(local, "result"):
                    local.result = result_factory()
                    with self.lock:
                        self.workers.append(local.result)
                self.invoke(callback, local.result, index, scheduled)
            finally:
                slots.release()

        index = 0
        while index < total:
            check_errors()
            scheduled = self.start_ns + int(index * 1_000_000_000 / self.rate)
            wait_until(scheduled)
            now = time.perf_counter_ns()
            if now >= self.end_ns:
                self.dropped_late += total - index
                self.scheduled += total - index
                break
            current_slot = int((now - self.start_ns) * self.rate / 1_000_000_000)
            if current_slot > index:
                skipped = min(current_slot - index, total - index)
                self.dropped_late += skipped
                self.scheduled += skipped
                index += skipped
                continue
            self.scheduled += 1
            if slots.acquire(blocking=False):
                try:
                    pending.add(executor.submit(task, index, scheduled))
                except BaseException:
                    slots.release()
                    raise
            else:
                self.dropped_capacity += 1
            index += 1
        wait_until(self.start_ns + int(admission_seconds * 1_000_000_000))
        self.admission_elapsed = (time.perf_counter_ns() - self.start_ns) / 1_000_000_000
        for future in pending:
            future.result()
        self.finished_ts = datetime.now(timezone.utc)
