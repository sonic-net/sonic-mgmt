"""Lifecycle wrapper; traffic policy and RPC execution belong to the blaster."""

import json
import logging
import time
from collections import Counter
from contextlib import ExitStack

import grpc

from tests.gnmi_benchmark.helpers import collect_resource_snapshot, gnmi_connection

logger = logging.getLogger(__name__)


class BenchmarkRunner:
    def run(self, host, fixture, blaster, result):
        """Prepare → warm up → measure → clean up → generate the chosen report."""
        with ExitStack() as cleanup:
            channel, stub = cleanup.enter_context(gnmi_connection(fixture))
            prepared = cleanup.enter_context(blaster.resources(host, stub))
            ready_seconds = None
            if blaster.warmup_seconds or blaster.rate:
                started = time.perf_counter_ns()
                grpc.channel_ready_future(channel).result(timeout=blaster.timeout_seconds)
                ready_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
            logger.info("GNMI_BENCHMARK_START %s", json.dumps(
                {"marker": blaster.marker, "blaster": blaster.name, "profile": blaster.profile()}))
            warmup = None
            if blaster.warmup_seconds:
                warmup = blaster.blast(stub, prepared, duration=blaster.warmup_seconds)
                statuses = Counter()
                for worker in warmup["workers"]:
                    statuses.update(worker["statuses"])
                response_errors = sum(w["response_errors"] for w in warmup["workers"])
                dropped = warmup["dropped_capacity"] + warmup["dropped_late"]
                summary = dict(marker=blaster.marker, completed=sum(statuses.values()),
                               iteration_status_counts=statuses, response_errors=response_errors, dropped=dropped)
                logger.info("GNMI_BENCHMARK_WARMUP_JSON %s", json.dumps(summary, sort_keys=True))
                if (not statuses.get("OK") or any(k != "OK" for k in statuses)
                        or response_errors or dropped):
                    raise RuntimeError("Warmup failed; measured phase not started: {}".format(summary))
            resources = collect_resource_snapshot(host)
            samples = blaster.blast(stub, prepared)
            resources += collect_resource_snapshot(host)
        return result.generate(samples=samples, warmup=warmup, connection_ready_seconds=ready_seconds,
                               resources=resources,
                               marker=blaster.marker, blaster=blaster.name, profile=blaster.profile())
