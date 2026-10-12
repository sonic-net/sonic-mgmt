# gNMI benchmark

An opt-in, **report-only** benchmark for VNET route Get→bypass Set requests.
There is one explicitly selected pytest entrypoint: `benchmark.py`. Configuration, SKU
selection and error handling live there; no benchmark-specific `conftest.py`
or `--benchmark-*` CLI options are needed.

## Run

Explicitly run `gnmi_benchmark/benchmark.py` with the normal sonic-mgmt
inventory/testbed arguments and `--run-stress-tests`. Use pytest `-k` to select
cases, for example:

```text
-k '1000routes and 100workers and closed-loop'
```

Run cases sequentially on one DUT. The route workload requires:

- HwSKU beginning with **`Cisco-8102`**, **`Cisco-8101`** or **`Cisco-8223`**.
  Missing or unsupported SKU skips before TLS setup.
- A single-ASIC DUT with TLS, native CONFIG_DB Get/Set, validation-bypass support,
  GCU and a Loopback0 IPv4 address.
- Exclusive configuration access and enough room for the generated inventory.
  Existing plus generated `VNET_ROUTE_TUNNEL` routes must not exceed 256,000.

## Configure

Edit `BENCHMARK_CONFIG` in [benchmark.py](benchmark.py):

| Setting | Purpose |
|---|---|
| `output_dir` | JSON report directory; default `/tmp/gnmi-benchmark` |
| `parameters` | Shared warmup, measurement duration and per-RPC timeout |
| `load_modes` | Closed-loop or open-loop, with offered iterations/s |
| `benchmarks` | Runner/Blaster factories, SKU prefixes, inventory and named load profiles |

`benchmarks["route-table"]["parameters"]["hwsku_prefixes"]` defines the allowed
SKU prefixes and is passed into the Blaster constructor alongside the inventory.
The entrypoint checks it before TLS setup. Direct callers may supply their own
`hwsku_prefixes` tuple; the base default `()` imposes no prefix restriction.

Parameters are merged in order: shared → workload → profile. The selected mode
sets traffic/rate, and the generated case ID sets the marker. `BENCHMARK_CASES`
expands this into eight pytest cases with fresh Runner and Blaster instances:

| Routes per RPC | Workers | Modes |
|---:|---|---|
| 1,000 | 10, 100, 200 | Closed and open loop |
| 20,000 | 10 | Closed and open loop |

Each case uses **60s warmup, 60s measured admission and 120s per-RPC timeout**.
Closed loop starts the next iteration after the previous one completes. Open
loop offers **500 iterations/s** independently of responses and drops arrivals
when capacity is full or their scheduled slot has expired. This rate is an
overload probe, not a demonstrated service capacity or agreed customer profile.
Eight cases require at least 16 minutes plus preparation, drain and restoration.

## Workload

Inventory is fixed at **256k routes**: twelve 20k-route VNETs plus one 16k-route
background VNET. `routes_per_request` controls batch size independently of this
inventory and must divide the largest VNET size exactly. Measurement rotates
through disjoint batches across the twelve largest VNETs; the smaller VNET stays
as background inventory.

Each iteration sends one explicit-key Get, then one bypass Set for the same
batch. A failed Get skips Set. Repeated iterations rewrite existing keys rather
than adding routes. Preload and cleanup are outside measurement. The helper
registers cleanup before mutation and restores the persistent configuration backup.

Get uses `ALL` and `JSON_IETF` with explicit CONFIG_DB paths. Set requests validation
bypass; SKU eligibility alone does not prove the server selected that path.
The benchmark checks RPC/response errors, not readback equality, forwarding
convergence or atomicity. Input limits are not demonstrated capacity.

## Results and error handling

Each completed run writes `<cid>-report.json` and attaches its report to the test
results. The marker is `<benchmark>-<profile>-<load-mode>`; `cid` distinguishes
repeated runs. Logs include both. Compare actual profile/load settings as well as
the marker.

Schema 12 uses `requests.get` and `requests.set`. Each has `entry_count`,
`count` (all issued RPCs that returned success/error), `error` (transport failures
plus response-level failures, counted once per RPC), and `latency_ms`.
`count - error` is the successful population represented by latency statistics.
No separate planned/started/unfinished counters, status breakdown, RPS or latency
threshold/pass-fail result is emitted. Nearest-rank percentiles and histogram
bounds retain their previous meaning; milliseconds are indicated by `latency_ms`.

`load` records concurrency once, configured measurement/warmup durations and
traffic pattern; open-loop also records `target_iterations_per_second`.
Measurement start/end and `elapsed_seconds` describe actual elapsed time including
waiting for issued RPCs. There is no separate drain/window timing output.
`warmup` records its own start/end, elapsed time, and per-method count/error/entry_count,
or null if disabled. Its requests are not included in measured latency.

Open-loop `dropped_iterations` is one total for planned Get→Set iterations that
were never issued. It is not an RPC error. Detailed scheduling delay/capacity/late
statistics remain internal to the blaster, not in the JSON. One iteration may
issue Get and Set; a failed Get prevents Set. Resource data remains boundary
snapshots, not continuously sampled peaks.

Resource snapshot counts and the top-level sampling descriptor are omitted from
the JSON. RPC timing implementation, backend-path labels and response-validation
descriptors are also omitted. Their removal does not change measurement or prove
a particular backend path. Latency `samples` and all 42 histogram buckets remain.

The schema version changes because keys/semantics changed. Existing reports are
unchanged; use `schema_version` to distinguish formats when reading mixed history.

Request timing includes serialization, queueing, transport, server work and
response decoding; explicit SetResponse error inspection is outside the timer.
Failed calls have no successful-latency sample. Warmup data is excluded; warmup
drops allow measurement, but warmup RPC/response errors stop the run.

The entrypoint logs ordinary exceptions and explicit `pytest.fail` outcomes from
dynamic TLS setup, Runner execution/cleanup and report writing, without re-raising.
Runner contexts unwind before logging. Skips and interrupts propagate normally.
Collection and fixture setup/teardown outside the test body remain pytest-managed.
No report is fabricated when execution or restoration prevents its generation.
**A green pytest outcome is not evidence of performance compliance or restored
device state.** Inspect errors and reports; timed-out server writes can outlive
the client and require cleanup verification before reuse.

## Code layout

| File | Responsibility |
|---|---|
| [benchmark_runner.py](benchmark_runner.py) | Connection/resources, warmup, measurement and cleanup |
| [blaster.py](blaster.py) | Workload, open/closed scheduling and raw RPC measurements |
| [benchmark_report.py](benchmark_report.py) | Measurement aggregation and JSON output |
| [helpers.py](helpers.py) | TLS, request construction and device resource helpers |

To add a workload, implement `Blaster.workload()` and, if needed, its resource
context, then register its factories and profiles in `BENCHMARK_CONFIG`.
The shared TLS fixture is unchanged.

[Design, timing boundary and report schema](../../docs/testplan/gnmi-benchmark-design.md)
