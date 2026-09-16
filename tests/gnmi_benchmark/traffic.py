"""Scheduling policies: neither policy knows about gNMI methods or paths."""

import math
import threading
import time
from collections import Counter
from datetime import datetime, timezone


class TrafficPhase:
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

    @property
    def elapsed_seconds(self):
        start = self.start_ns if self.duration_seconds or self.rate else min(w.started_ns for w in self.workers)
        finished = max([w.finished_ns for w in self.workers] +
                       [self.start_ns + int(self.admission_elapsed * 1_000_000_000)])
        return (finished - start) / 1_000_000_000

    @property
    def drain_seconds(self):
        if self.rate:
            return max(0, self.elapsed_seconds - self.admission_elapsed)
        return max(0, self.elapsed_seconds - self.duration_seconds) if self.duration_seconds else 0

    @property
    def statuses(self):
        result = Counter()
        for worker in self.workers:
            result.update(worker.statuses)
        return result

    @property
    def response_errors(self):
        return sum(w.response_errors for w in self.workers)


class ClosedLoop(TrafficPhase):
    """Preserve fixed per-worker quotas in count mode; no pacing between calls."""

    def run(self, executor, callback, result_factory, counts):
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
        return self


class UniformOpenLoop(TrafficPhase):
    """Fixed arrival clock with nonblocking admission and no catch-up bursts.

    At most concurrency tasks (queued plus executing) are admitted. A late clock
    skips expired slots; exhausted capacity drops the current slot, never waits
    for a response. Only drain waits for admitted operations to finish.
    """

    def run(self, executor, callback, result_factory, counts):
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
        return self
