# gNMI benchmark

An opt-in, **report-only** benchmark for VNET route Get→bypass Set requests.
There is one pytest entrypoint: `test_gnmi_benchmark.py`. Configuration, SKU
selection and error handling live there; no benchmark-specific `conftest.py`
or `--benchmark-*` CLI options are needed.

## Run

Run `gnmi_benchmark/test_gnmi_benchmark.py` with the normal sonic-mgmt
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

Edit `BENCHMARK_CONFIG` in [test_gnmi_benchmark.py](test_gnmi_benchmark.py):

| Setting | Purpose |
|---|---|
| `output_dir` | JSON report directory; default `/tmp/gnmi-benchmark` |
| `parameters` | Shared warmup, measurement duration and per-RPC timeout |
| `load_modes` | Closed-loop or open-loop, with offered iterations/s |
| `benchmarks` | Runner/Blaster factories, inventory and named load profiles |

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

Schema 10 contains separate bodies such as `requests["get:1000"]` and
`requests["set:1000"]`:

- Per-RPC outcome counts, successful-call latency in **ms**, percentiles and histogram.
- **1,000ms per-request** evaluation. Slow requests, RPC/response errors and measured
  drops produce an error log, without failing pytest. A low average/P95 is not a pass.
- Scheduling in **iterations**: open-loop arrivals, drops, start delay and drain.
  One iteration contains Get plus Set; it is not one RPC.
- Resource snapshots before/after measurement, not peaks during load.

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
| [benchmark_report.py](benchmark_report.py) | Aggregation, performance evaluation and JSON output |
| [helpers.py](helpers.py) | TLS, request construction and device resource helpers |

To add a workload, implement `Blaster.workload()` and, if needed, its resource
context, then register its factories and profiles in `BENCHMARK_CONFIG`.
The shared TLS fixture is unchanged.

[Design, timing boundary and report schema](../../docs/testplan/gnmi-benchmark-design.md)
