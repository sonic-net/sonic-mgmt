# gNMI benchmark

## Purpose

Measure how SONiC gNMI request latency and throughput change with request size
and offered load. The framework separates test lifecycle, traffic generation
and reporting so different workloads can use the same measurement approach.

A **request** is an individual RPC; an **iteration** is one execution of a
workload and may contain multiple requests. Latency is measured per request,
while scheduling controls iterations. The scenario included in this PR is
described in [Current blaster: route-table](#current-blaster-route-table).

## Workflow

```mermaid
flowchart TB
    subgraph Runner["Runner · lifecycle"]
        direction LR
        subgraph Preparation["Preparation"]
            Connect["Connect"] --> Resources["Prepare data"]
        end
        subgraph Blaster["Blaster · traffic"]
            Warmup["Warm up (optional)"] --> Measure["Measure"] --> Drain["Drain"]
        end
        subgraph Restoration["Restoration"]
            Cleanup["Release resources"]
        end
        Resources --> Warmup
        Drain --> Cleanup
    end
    subgraph Report["Report · results"]
        Summarize["Summarize"] --> Evaluate["Evaluate"]
    end
    Cleanup --> Summarize
```

| Part | Responsibility |
|---|---|
| Runner | Coordinate phases and ensure resources are released, including on failure. |
| Preparation | Establish the connection and prepare workload-specific data and requests. |
| Blaster | Execute optional warmup and measured traffic; stop admission at the configured limit and drain outstanding work. |
| Restoration | Remove test resources and restore the environment before reporting. |
| Report | Turn completed measurements into statistics and a pass/fail result. |

Warmup and measurement use the same workload, but warmup samples are excluded
from results. The Runner decides whether warmup succeeded before starting
measurement. The Report consumes measurements without controlling execution.
A preparation or restoration failure prevents a completed benchmark report.

## Load model

| Load model | Behavior | Question it answers |
|---|---|---|
| Closed loop | Each worker starts another iteration after its previous one finishes. | How does performance change with concurrency? |
| Open loop | Iterations are offered at a fixed rate, with bounded outstanding work. Unadmitted arrivals are dropped. | How much offered load can the system sustain? |

Experiments control workers, duration or iteration count, and optional warmup.
Open loop additionally sets the arrival rate in **iterations/s**. The workload
defines request types and sizes; iterations/s is not interchangeable with RPC/s.

Requests are prepared before load and share a persistent connection, keeping
setup work out of the measured workload. Open loop drops arrivals it cannot
admit rather than building an unbounded queue or sending catch-up bursts.

## Measurement and interpretation

Each request is timed independently around its client call. An iteration with
multiple requests produces separate latency samples, not a combined latency.

```mermaid
flowchart LR
    Start["Start timer"] --> Call["Request / response"] --> Stop["Stop timer"] --> Record["Record outcome"]
```

Latency includes serialization, transport, server work and response decoding.
Preparation, warmup and restoration are outside the timer. Failed calls are
counted as errors rather than included in successful-request latency statistics.

| Result | Interpretation |
|---|---|
| Request latency | Client-observed distributions grouped by request type and size. |
| Throughput | Completed work per second, with the unit and interval stated: RPC/s per request type, or iterations/s for the workload. |
| Errors and drops | RPC failures and unsent arrivals are counted separately from successful-call latency. |
| Drain time | Time spent finishing admitted work after the load window ends. |

Per-request rates use the full measurement interval, including drain. For
duration runs, the report also records successful iterations completed within
the admission window. Workload-specific units such as entries/s must be derived
from the actual work completed, rather than assumed from the offered rate.

The current pass criterion is **every measured request ≤1,000 ms**, with no
RPC/response errors or dropped arrivals. A mean or P95 below 1,000 ms does not
establish a pass.

Interpret results with these boundaries:

- Read open-loop latency together with its drop rate. Fast admitted requests do
  not show that the full offered rate was sustained.
- Keep admission-window throughput separate from full-run averages that include
  drain. Long-drain runs do not establish steady-state capacity.
- RPC success establishes response-level success, not application correctness
  or completion of downstream effects.
- Compare versions using the same data, load, transport and repeated runs.
  One run demonstrates observed behavior, not an internal cause or reliable speedup.

For CLI examples, defaults and extension details, see the
[benchmark README](../../tests/gnmi_benchmark/README.md).

## References

- [gRPC benchmarking](https://grpc.io/docs/guides/benchmarking/): a compact overview
  organized around test design, scenarios and infrastructure.
- [k6 test lifecycle](https://grafana.com/docs/k6/latest/using-k6/test-lifecycle/):
  separate preparation, repeated workload and teardown.
- [k6 open and closed models](https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/open-vs-closed/):
  distinguish fixed concurrency from independent arrival rates.
- [arc42 architecture canvas](https://arc42.org/canvas/): communicate goals,
  structure and key constraints as a concise design overview.

## Current blaster: route-table

This PR provides [RouteTableBlaster](../../tests/gnmi_benchmark/blaster.py), a
bulk configuration workload. Each iteration performs **Get → Set** for existing
VNET routes in CONFIG_DB: one Get reads explicit keys, and one table-level Set
rewrites that batch with validation bypass requested. Set uses prepared values,
not the Get response; a failed Get skips Set. Other workloads can supply a
different request sequence while reusing the framework.

The default inventory contains **256,000 routes across 13 VNETs**: 12 × 20,000
measured routes plus 16,000 background routes. Requests cycle through disjoint
batches across measured VNETs. Batch size divides the measured VNET size so every
request carries the same number of routes. Varying batch size preserves inventory
and eligible keys, separating request-size effects from database-size effects.
Short runs may not visit every batch.

The scenario requires a single-ASIC DUT with TLS, GCU and Loopback0 IPv4 support.
Preparation checks route capacity, backs up configuration and preloads routes;
restoration removes test resources and restores the backup. Runs need exclusive
configuration access. Client drain does not prove timed-out server writes have
stopped, so restoration must be checked before device reuse.

Get and Set have separate latency distributions. A successful iteration contains
two RPCs; its batch size converts iteration throughput to route entries/s per
direction. The benchmark does not check readback or forwarding convergence, or
assert that bypass was used. Get may read a CONFIG_DB checkpoint.

### Observed baseline (2026-09-17–18)

**Latency increases with concurrency and request size. More workers do not
preserve response time under this load.**

![Load impact: Get and Set mean latency increases with workers and batch size](gnmi-benchmark-results/load-impact.svg)

#### Experiment

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

#### Findings

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
