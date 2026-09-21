# gNMI benchmark

**Three main files: runner, blaster, benchmark report.**

| File | Read this for |
|---|---|
| [benchmark_runner.py](benchmark_runner.py) | `BenchmarkRunner.run`: acquire resources, call warmup/measurement, clean up, hand measurements to the report |
| [blaster.py](blaster.py) | Abstract `Blaster`, open/closed-loop scheduling, thread pools, RPC execution and `RouteTableBlaster.workload()` |
| [benchmark_report.py](benchmark_report.py) | `BenchmarkReport.generate`: statistics, JSON report and output |
| [helpers.py](helpers.py) | Shared TLS, resource acquisition/restoration and request-building helpers |

`test_gnmi_benchmark.py` is the thin pytest entrypoint; `conftest.py` registers CLI
options. There are no separate client, environment, scheduler or workload packages.

## Main entrypoint

```python
from tests.gnmi_benchmark.benchmark_runner import BenchmarkRunner
from tests.gnmi_benchmark.blaster import RouteTableBlaster
from tests.gnmi_benchmark.benchmark_report import BenchmarkReport

blaster = RouteTableBlaster(
    route_distribution={16000: 1, 20000: 12},
    routes_per_request=20000,
    concurrency=20,
    logical_requests=1000,
    marker="routes-20k-total-256k",
)
result = BenchmarkRunner().run(duthost, gnmi_tls, blaster, BenchmarkReport())
result.write("/tmp/gnmi-benchmark")
```

`RouteTableBlaster.workload()` is the business action: select a VNET, **Get its
route batch, then bypass Set the same batch**. The default inventory is
12 VNETs × 20,000 + 1 × 16,000 = **13 VNETs / 256,000 routes**.
It is a test profile, not a claim about a particular customer's actual distribution.
All route batches are preloaded before warmup/measurement and reused read-only.
Only the largest VNETs participate in measurement; smaller VNETs remain background
inventory. `routes_per_request` divides each measured VNET into disjoint batches.
Selection cycles through measured VNETs before advancing to their next batch.
Short/dropped runs may not visit all batches; repeats rewrite
the same keys rather than creating more routes.
Count/rate/concurrency apply to complete iterations, not individual RPCs.
Get failure skips Set. The report groups individual RPC durations by request type and route count,
without adding Get and Set together. This is a response-level test, not an atomic transaction or
forwarding convergence check.

## Lifecycle and extension

The runner enters the connection context and `blaster.resources(host, stub)`, which
returns prepared requests. It owns both contexts through an ExitStack. Resource
helpers register rollback before mutations; workers drain before cleanup starts.
Backup restoration is attempted even if route-key removal fails. Reporting occurs
only after cleanup succeeds. No concrete blaster or report class is imported by
the runner.

For each phase it calls `blaster.blast(stub, prepared, duration=...)`. Blaster
selects the scheduling policy, owns its thread pool, drains admitted work and
returns raw timestamps, counters and per-worker sample lists. It does not define
report fields, throughput or histograms. BenchmarkReport derives those statistics.
Inside `blaster.py`, abstract `LoadLoop` owns the pool lifecycle, common clock and
in-flight/sample bookkeeping. `ClosedLoop` and `OpenLoop` inherit it and implement
only `_schedule()`. Both reuse `run()` and `invoke()`, including drain on errors.
Warmup and measurement use separate
pools and counters, but share the same connection and prepared requests. Runner
checks warmup outcomes and decides whether to proceed; it implements no arrival
clock, worker loop or concurrency policy.

To add a scenario, subclass `Blaster` in `blaster.py` and implement
`workload(session, prepared)`. Override `resources(host, stub)` only when preparation is
needed; return a context manager from a resource helper. Do not put concurrency
loops or cleanup commands inside `workload()`. Inherited defaults are 4 workers,
100 iterations, 120-second per-RPC timeout, closed-loop traffic and no warmup.
RouteTableBlaster defaults to 1,000 iterations; duration mode instead uses a time window.

To change reporting, pass an object implementing:

```python
class CountReport:
    def generate(self, *, samples, warmup, connection_ready_seconds, resources, marker, blaster, profile):
        completed = sum(sum(worker["statuses"].values()) for worker in samples["workers"])
        return {"marker": marker, "completed": completed}
```

The runner returns whatever `generate()` returns. The standard BenchmarkReport
provides `to_dict()`, `write()` and `failed`; it does not control warmup or access
the DUT. Measurement inputs are plain data, not runner/worker objects.
The report defines elapsed/drain time, throughput, sample populations and output
fields. Runner checks raw warmup outcomes before deciding to start measurement;
the report never makes that execution decision.

## CLI examples

Use the normal sonic-mgmt inventory/testbed arguments with
`gnmi_benchmark/test_gnmi_benchmark.py`.

```text
--run-stress-tests --benchmark-blaster route-table
--benchmark-blaster-params '{"route_distribution":{"16000":1,"20000":12},"routes_per_request":20000}'
--benchmark-marker routes-20k-total-256k
--benchmark-concurrency 20 --benchmark-logical-requests 1000
--benchmark-warmup 60 --benchmark-timeout 120
```

Uniform open-loop adds `--benchmark-traffic open-loop --benchmark-rate 500`.
This means 500 Get→Set iterations/s, not 500 RPCs/s. Capacity/late drops are explicit
and fail the test, without being fabricated RPC failures or latency samples.

The quotes above are for direct shell invocation of pytest. When embedding the
compact JSON inside `run_tests.sh -e "..."`, do not pass literal outer single
quotes through to pytest; its JSON argument must start with `{`.

There is one concrete scenario: `RouteTableBlaster`. The abstract `Blaster` only
defines shared settings and the extension contract; it is not another test.

| Name | Scenario parameters | Workload |
|---|---|---|
| `route-table` | `route_distribution`: inventory per VNET → VNET count; `routes_per_request`: batch size | Each iteration reads and bypass-writes one batch within a largest-size VNET |

There is no method/mode selector. The concrete blaster's `workload()` defines what
one logical request does; RouteTableBlaster always uses Get→Set.

It accepts inherited load settings and `marker`. JSON parameters initialize the
blaster; explicitly provided CLI load flags override them. Omitted flags retain
its defaults. `--benchmark-blaster route-table` is optional since it is the only
supported scenario. The old `--benchmark-workload` and scenario flags
are replaced by `--benchmark-blaster` / `--benchmark-blaster-params`.

`routes_per_request` must be a positive divisor of the largest VNET size; no
partial batches are measured. Distribution keys must be 1–20,000 and counts positive integers; their weighted
sum must not exceed **256,000**, including existing CONFIG_DB routes on the DUT.
The default full-capacity profile therefore requires no pre-existing route entries.
Generated routes get isolated VNETs sharing one test VXLAN tunnel and persistent
config backup/restoration. Setup issues one bypass Set per VNET, excluded from
measurement. Every measured Set also requests bypass; there is no bypass toggle,
Regular mode or arbitrary payload file option.
This requests bypass, not authentication bypass or proof of server fast-path
execution. The shared `gnmi_tls` fixture is unchanged.

Each Get contains explicit native CONFIG_DB paths for every compound route key
of the selected batch; it is not an empty Get or a full-table query. A single Get
with 20k paths may be expensive and requires device validation. No wildcard support
is assumed. Responses are checked for RPC success, not compared against the payload.

## Measurement limits

Schema 10 reports per-request latency, outcome counts and throughput by request type and route count,
plus scheduling evidence and resource boundary samples. Marker identifies the
scenario; `benchmark.profile` records VNET count, route distribution, total routes,
limit and selection policy. Raw request contents and credential metadata are never echoed.

`requests["get:20000"]` and `requests["set:20000"]` are independent report bodies, each with counts,
statuses, latency histograms and `latency_requirement`. Only executed request types
appear; an unsent Set is not a zero-latency success. Each RPC
timer surrounds the stub call, including client queueing, transport and decoding,
but excluding response-error inspection. Successful Gets remain in Get statistics
even if their subsequent Set fails; failed Gets skip Set. Preload and warmup calls
are excluded from all measured populations. No combined latency or sum of Get/Set
percentiles is reported. The requirement is **at most 1,000 ms for each request**,
not for the average or P95: `within_limit` / `exceeded` count successful calls on
either side of that boundary. Failed RPCs are counted separately and also fail the
test. A successful request over 1,000 ms makes the benchmark fail after writing its
report. RPC timeout remains a separate setting so slow requests can be measured.
`load.iterations` describes execution scheduling only; it is not an RPC count.

Each request timer starts immediately before its stub call and ends at the
decoded return; SetResponse inspection is excluded.
Setup, warmup and cleanup are excluded. Client/HTTP2 queueing, serialization,
transport and server work remain included. This is not pure network RTT.

The local behavioral checks use mocked RPCs and device lifecycle. Limits of
500 workers, 20k entries per VNET and 256,000 total routes are limits, not demonstrated capacity.
Timed-out server writes may outlive the client; inspect cleanup before reuse.

[Detailed design and reporting](../../docs/testplan/gnmi-benchmark-design.md)
