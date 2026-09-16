# gNMI benchmark

Configurable grpcio load generation for SONiC gNMI Get/Set, reporting
**client-observed RPC latency, throughput and request outcomes**.

[RTT diagram](../../docs/testplan/gnmi-benchmark-design.md#what-does-the-measured-rtt-consist-of) ·
[Parameters](../../docs/testplan/gnmi-benchmark-design.md#load-generator-and-supported-parameters) ·
[JSON reports](../../docs/testplan/gnmi-benchmark-design.md#report-and-evidence)

**Timing:** the retained client-call metric includes serialization, possible
client queueing, transport, server work and response decoding. Setup, explicit
readiness, warmup and response-error checks are outside per-RPC timing.
It is not pure network RTT; component costs are not separately measured.

## How to observe

[Vertical Regular/bypass flow](../../docs/testplan/gnmi-benchmark-design.md#what-does-the-measured-rtt-consist-of).
Server processing is already inside client-call duration. Component costs and a
numeric total-error bound are not established.
[Timing summary](../../docs/testplan/gnmi-benchmark-design.md#timing-summary-and-estimation-limits).

Success requires gRPC `OK` and no explicit SetResponse/UpdateResult error.
Inspect errors after timing and exclude them from successful latency. These are
response-level checks, not forwarding verification.
[Verification rules](../../docs/testplan/gnmi-benchmark-design.md#verification-rules).

## JSON reports

`<cid>-report.json` uses schema 3 for single operations and schema 4 for Get→Set,
and is also emitted to logs and CustomMsg.
It contains device/workload identity, counts/statuses, latency, throughput,
execution windows and resource snapshots.
[JSON report shape and templates](../../docs/testplan/gnmi-benchmark-design.md#report-and-evidence).

## Usage

**Current load model: closed loop.** Each worker waits for its own RPC/group to
finish before issuing the next one. Slower responses lower the offered rate;
this is not a fixed-RPS capacity test. See the
[traffic generation diagram](../../docs/testplan/gnmi-benchmark-design.md#traffic-generation-design--closed-loop)
and [open-loop future-work placeholder](../../docs/testplan/gnmi-benchmark-design.md#open-loop-runner--future-work).

Common scheduling/timing controls are separate from workload-specific request
data and preparation. The existing workloads do not yet accept arbitrary gNMI
paths; VNET options apply only to VNET traffic.

### VNET example: combined Get → Set, 1,000 groups

Use the same single-ASIC DUT/image and these parameters for both runs:

```text
--run-stress-tests --benchmark-operation get-set --benchmark-workload vnet-route-tunnel
--benchmark-workload-params '{"entry_count":10,"prepare":true}'
--benchmark-concurrency 2 --benchmark-warmup 60
--benchmark-logical-requests 1000 --benchmark-duration 0 --benchmark-timeout 120
```

Add `--benchmark-bypass` only for the bypass-requested run. Valid-route setup
creates an isolated VXLAN tunnel and VNET using GCU before load generation.
Warmup inserts the same-shaped route batch; measurement repeats those values.
Names differ only by a fixed-length unique suffix. Cleanup removes generated
routes and prerequisites and restores the pre-test persistent config file before
the existing TLS fixture rolls back. Do not overlap other configuration writers.
This tests configuration RPCs, not packet forwarding. A failed warmup prevents
measurement; do not assume warmup removes regular GCU per-request costs.

This uses 1,000 measured **groups per run**: an empty Get followed by Set after
Get succeeds, with 10 routes per Set. Get failure skips Set and fails the group.
All-success execution produces 2,000 RPCs. Group latency and separate Get/Set
metrics are reported; warmup remains time-based. Ensure the outer test-plan limit
accommodates the slower run.

`--benchmark-workload-params` accepts workload-specific JSON, not nested CLI flags.
VNET uses `entry_count`, `prepare` (default false), or `payload_file` instead of
`entry_count`. Other workload types are `empty` and `port-description`; they take
no parameters. Reports record the resolved workload configuration in `load.workload`
alongside VNET-specific payload fields.

Run `gnmi_benchmark/test_gnmi_benchmark.py` through the normal sonic-mgmt runner.
Example fixed-count Get workload:

```text
--run-stress-tests --benchmark-operation get --benchmark-logical-requests 100
--benchmark-concurrency 4 --benchmark-output-dir <report-directory>
```

| Capability | Configuration |
|---|---|
| Parallel load | 1–500 client workers per invocation; default 4, sharing one TLS channel/stub |
| Run length | 1–1,000,000 requests, or `--benchmark-duration` in seconds |
| Warmup / deadline | Optional `--benchmark-warmup` (default 0); per-RPC `--benchmark-timeout` (default 120 s) |
| Set payload | PORT description, JSON batch file, or up to 20k generated shared records per RPC |
| Backend selection | `--benchmark-bypass` explicitly requests batch Set validation bypass; authentication remains separate |

**Limits:** 500 workers is a client configuration limit, not server capacity.
Successful-latency statistics exclude errors. Verify cleanup after timed-out writes.
