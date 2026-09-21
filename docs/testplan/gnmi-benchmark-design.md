# gNMI benchmark

## Purpose

Measure how SONiC gNMI Get and Set latency and throughput change with request
size and concurrent load. The benchmark keeps stored data separate from request
batch size so each experiment can vary one factor at a time.

The current scenario reads and rewrites VNET routes in CONFIG_DB. It measures
client-observed RPC performance, not forwarding convergence or server-only
execution time.

## Workflow

```mermaid
flowchart LR
    Prepare --> Warmup["Warm up"] --> Measure --> Restore --> Report
```

Preparation establishes the connection and preloads test data. Optional warmup
runs the same workload without contributing to results. Measurement stops
admitting new work at the configured limit and waits for outstanding calls to
finish. Test resources are restored before the report is generated.

The design separates three responsibilities:

| Component | Responsibility |
|---|---|
| [Runner](../../tests/gnmi_benchmark/benchmark_runner.py) | Manage preparation, measurement and restoration. |
| [Blaster](../../tests/gnmi_benchmark/blaster.py) | Define the workload and generate open- or closed-loop traffic. |
| [Report](../../tests/gnmi_benchmark/benchmark_report.py) | Summarize completed measurements and evaluate the latency requirement. |

This separation lets a new workload reuse the lifecycle and reporting, while a
different report can reuse the same measurements.

## Workload and load model

Each iteration performs **Get → Set** for one batch of existing routes. Get reads
explicit CONFIG_DB keys in one RPC; Set sends one table-level update containing
the same batch, with native validation bypass requested. This measures the
intended bulk configuration workload. Get and Set are timed separately, and a
failed Get skips Set. Set uses prepared values rather than the Get response.

The default inventory contains **256,000 routes across 13 VNETs**: 12 × 20,000
measured routes plus 16,000 background routes. Requests cycle through disjoint
batches across the measured VNETs. Changing batch size preserves the inventory
and eligible key set, separating request-size effects from database-size effects.
Batch size must divide the measured VNET size so every request carries the same
number of routes. Short runs may not visit every batch.

| Load model | Behavior | Question it answers |
|---|---|---|
| Closed loop | Each worker starts another iteration after its previous one finishes. | How does performance change with concurrency? |
| Open loop | Iterations are offered at a fixed rate, with bounded outstanding work. Unadmitted arrivals are dropped. | How much offered load can the system sustain? |

Experiments control inventory, routes per request, workers, duration or iteration
count, and optional warmup. Open loop additionally sets the arrival rate in
**iterations/s**; one successful iteration contains two RPCs.

Requests are prepared before load and share a persistent connection, keeping
setup work out of the measured workload. Open loop drops arrivals it cannot
admit rather than building an unbounded queue or sending catch-up bursts.

The scenario runs on a single-ASIC DUT with TLS, GCU and Loopback0 IPv4 support.
Setup checks route capacity and backs up configuration; cleanup removes test
resources and restores the backup. Runs require exclusive configuration access.
A setup or restoration failure prevents a completed benchmark report.
Client drain alone does not prove that timed-out server writes have stopped;
restoration must be checked before reusing the device.

## Measurement and interpretation

| Result | Interpretation |
|---|---|
| Get / Set latency | Separate client-observed distributions for each method and batch size, including transport and server work. |
| Throughput | Completed Get→Set iterations in the admission window; batch size converts this to route entries/s per direction. |
| Errors and drops | RPC failures and unsent arrivals are counted separately from successful-call latency. |
| Drain time | Time spent finishing admitted work after the load window ends. |

Setup, preload, warmup and restoration are excluded from RPC latency. The current
pass criterion is **every measured request ≤1,000 ms**, with no RPC/response errors
or dropped arrivals. A mean or P95 below 1,000 ms does not establish a pass.

Interpret results with these boundaries:

- Read open-loop latency together with its drop rate. Fast admitted requests do
  not show that the full offered rate was sustained.
- Keep admission-window throughput separate from full-run averages that include
  drain. Long-drain runs do not establish steady-state capacity.
- RPC success does not verify returned values, post-Set readback, forwarding
  convergence or actual bypass execution. Get may read a CONFIG_DB checkpoint.
- Compare versions using the same inventory, load, transport and repeated runs.
  One run demonstrates observed behavior, not an internal cause or reliable speedup.

For CLI examples, defaults and extension details, see the
[benchmark README](../../tests/gnmi_benchmark/README.md).

## Observed baseline (2026-09-17–18)

**Latency increases with concurrency and request size. More workers do not
preserve response time under this load.**

![Load impact: Get and Set mean latency increases with workers and batch size](gnmi-benchmark-results/load-impact.svg)

### Experiment

Both sweeps use 256,000 stored routes (12 × 20,000 measured + 16,000 background),
60 s admission, no warmup, a 120 s per-RPC timeout and one persistent TLS channel.
Open loop offers 500 iterations/s; closed loop refills workers after completion.

| Sweep | Fixed | Varied |
|---|---|---|
| Concurrency | 20,000 routes/RPC | 2, 5, 10, 50, 100, 500 workers; both load models |
| Batch size | 100 workers | 100, 500, 1,000, 2,000 routes/RPC; both load models |

Tests used a single-ASIC Cisco-8102-C64 running original SONiC `20260510.14`,
without server timing instrumentation, over TLS-over-SSH. The benchmark was
overlaid on sonic-mgmt `202605` at `72ffcc20e210411f54c7b500ef9a9f96267876ed`;
the public-master fixture stack was not physically validated. Each point is one
run, and the batch sweep resumed in a later device session.

### Findings

1. **Concurrency increases latency.** At 20k routes/RPC, closed-loop workers
   2 → 100 raise mean Get **3.43 → 59.45 s** and Set **6.70 → 92.80 s**.
2. **Larger batches reduce completed iterations.** At 100 workers, batches
   100 → 2,000 raise mean Get **0.42 → 8.61 s** and Set **0.48 → 8.59 s**.
   Across both load models, window throughput is roughly **10k–11.5k route
   entries/s per direction** in this sweep.
3. **No reported run meets the per-request threshold.** All 18 reports contain
   requests above 1 s, despite zero RPC errors. Open-loop drops are
   **77.80–98.63%** in the batch sweep and **99.66–99.96%** in the worker sweep.

**18/20 attempted points produced reports.** Both 20k/500-worker runs lost
management connectivity, preventing final sampling, cleanup and report emission;
their cause is unconfirmed and they have no plotted values. At 20k with 50/100
workers, most or all iterations finish after the admission window.

The [results CSV](gnmi-benchmark-results/results.csv) contains all 18 reported
points, including counts, mean/P95, errors, drops and drain. Raw logs remain local.

## References

- [gRPC benchmarking](https://grpc.io/docs/guides/benchmarking/): a compact overview
  organized around test design, scenarios and infrastructure.
- [k6 test lifecycle](https://grafana.com/docs/k6/latest/using-k6/test-lifecycle/):
  separate preparation, repeated workload and teardown.
- [k6 open and closed models](https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/open-vs-closed/):
  distinguish fixed concurrency from independent arrival rates.
- [arc42 architecture canvas](https://arc42.org/canvas/): communicate goals,
  structure and key constraints as a concise design overview.
