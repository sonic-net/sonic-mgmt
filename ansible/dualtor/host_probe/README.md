# DualToR test-server capability probe

## Background

DualToR topologies in this test framework are simulated: a mux simulator, a
NIC simulator and OVS bridges stand in for real Y-cables, and a single test
server usually hosts several testbeds. When DualToR nightly runs are
unstable it is difficult to separate four candidate causes — the test code,
the simulator, OVS, or the machine the testbed happens to sit on.

Two observations from a 30-day nightly window motivated this probe.

**Failure rate varies by more than an order of magnitude between test
servers running the identical topology.** Comparing two servers on the same
`dualtor-aa-56` topology, with the same simulator stack, gave failure rates
that differed by roughly 40x.

**Co-tenancy does not explain it.** Binning runs by the number of testbeds
active on the same host in the same hour shows failure rate *falling* as
co-tenancy rises (3.26% / 2.93% / 1.87% for one / two / three concurrent
testbeds). Repeating the comparison *within* individual servers, to remove
the confound of good servers happening to run busier, gives an inconsistent
direction and a magnitude inside 2–4x — far smaller than the spread between
servers. The server a testbed lands on matters much more than how many
neighbours it has.

A plausible mechanism is already on record: two servers running the same
`dualtor-120` topology behaved very differently, and differed mainly in CPU
generation, core count, L3 cache size, and how many speculative-execution
mitigations were active. The mux switchover path is syscall and VM-exit
heavy, because a separate `ovs-ofctl` process is spawned per flow
modification — precisely the path those mitigations tax.

This probe turns that one-off comparison into a repeatable per-server
number, so DualToR topologies can be placed deliberately rather than by
accident.

## What it measures

| Metric | How | Why |
|---|---|---|
| `spawn_only` | `ovs-ofctl --version` | Never contacts the OVS daemon, so it isolates pure process creation cost. This is the cleanest available signal of host capability. |
| `ovs_read` | `dump-flows` on a scratch bridge | Per-server OVS read baseline. |
| `ovs_write` | `add-flow` + `del-flows` on that bridge | Per-server OVS write baseline. |

Each is reported as count / min / p50 / p95 / p99 / max / mean, together
with the host context that plausibly explains differences: CPU model,
logical CPU count, max clock, L3 size, the number of active speculative
execution mitigations, OVS version, load average, and how many live mux
bridges the server already carries.

## How to read the result

- If **`spawn_only`** differs between servers far more than `ovs_write`
  does, the amplifier is process creation. That is a host specification and
  placement question: move high fan-out DualToR topologies (120-port,
  56-port) onto stronger servers.
- If **`ovs_write`** is what diverges, the OVS layer is implicated, and the
  per-server numbers belong in the separate OVS responsiveness
  investigation rather than in placement decisions.

## Scope

This is a read-only diagnostic. It deliberately does **not** modify
`ansible/roles/vm_set/files/mux_simulator.py`, and it makes no
recommendation about simulator worker counts or call batching. Simulator
internals and OVS daemon responsiveness are tracked separately; this probe
only produces per-server numbers that those investigations can consume.

## Safety

The probe creates and destroys its own scratch bridge named
`dtprobe-<pid>`. That name cannot match the `mbr-<...>-<vm_set>-<idx>`
pattern that the mux simulator scans for, so a running simulator will never
adopt it. Cleanup runs on success, on exception and on `Ctrl-C`. No testbed
configuration and no existing file is modified.

The probe is intentionally small: it creates four scratch ports by default
and issues a few dozen trivial commands. It is a latency probe, not a load
test, and is safe to run on a server that is currently executing tests —
though running it on an idle server gives a cleaner baseline.

## Usage

```bash
# on a server with a high DualToR failure rate
sudo python3 dualtor_host_probe.py --json probe-serverA.json

# on a server with a low DualToR failure rate
sudo python3 dualtor_host_probe.py --json probe-serverB.json

# compare, anywhere
python3 dualtor_host_probe.py --compare 'probe-*.json'
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `--ports` | `4` | Scratch ports to create. Small on purpose. |
| `--iterations` | `50` | Samples per measurement. |
| `--json PATH` | — | Write the full result set for later comparison. |
| `--no-sudo` | off | Do not prefix commands with `sudo`. |
| `--compare GLOB...` | — | Render a ranked cross-server table and exit. |

`--compare` sorts servers by capability score (lower is better, defined as
median spawn cost plus median trivial OVS write cost) and prints the spread
between the best and worst server.

## Requirements

Runs on the Linux test server that hosts the mux simulator. Needs Python 3,
`ovs-vsctl` and `ovs-ofctl` on `PATH`, and permission to create an OVS
bridge (the script adds `sudo` automatically when not run as root). The
`--compare` mode reads only JSON files and runs anywhere.
