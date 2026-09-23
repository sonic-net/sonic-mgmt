#!/usr/bin/env python3
"""DualToR test-server capability probe.

Why this exists
---------------
DualToR topologies are simulated with a mux simulator, a NIC simulator and
OVS bridges rather than real Y-cables, and a single test server usually
hosts several testbeds. When DualToR nightly runs are unstable it is hard
to tell whether the cause is the test code, the simulator, OVS, or simply
the machine the testbed happens to sit on.

Measuring a 30-day nightly window shows that DualToR failure rate varies by
more than an order of magnitude between test servers running the *identical*
topology, while being essentially independent of how many testbeds share a
host. Binning runs by the number of testbeds active on the same host in the
same hour does not show the rise that a contention explanation predicts, so
host identity rather than co-tenancy is what separates good servers from
bad ones.

A likely mechanism is already documented: two servers running the same
dualtor-120 topology behaved very differently, and they differed mainly in
CPU generation, core count, L3 size and how many speculative-execution
mitigations were active. The mux switchover path is syscall and VM-exit
heavy, because a separate `ovs-ofctl` process is spawned per flow
modification, and that is exactly the path such mitigations tax.

This probe turns that observation into a repeatable per-host number so
DualToR topologies can be placed on servers deliberately instead of by
accident.

What it measures
----------------
  * `spawn_only` - `ovs-ofctl --version`, which never contacts the OVS
    daemon. This isolates pure process creation cost and is the cleanest
    available signal of host capability.
  * `ovs_read` - one `dump-flows` against a scratch bridge.
  * `ovs_write` - one `add-flow` plus `del-flows` against that bridge.

Reading the result: if `spawn_only` differs between servers far more than
`ovs_write` does, the amplifier is process creation, which is a host
specification and placement question. If `ovs_write` is what diverges, the
OVS layer is implicated and the numbers belong in the separate OVS
responsiveness investigation instead.

Scope
-----
This is a read-only diagnostic. It deliberately does not modify
`ansible/roles/vm_set/files/mux_simulator.py`, and it makes no
recommendation about simulator worker counts or call batching; simulator
internals and OVS daemon responsiveness are tracked separately. The probe
only produces per-host numbers.

Usage
-----
    sudo python3 dualtor_host_probe.py --json probe-serverA.json
    sudo python3 dualtor_host_probe.py --json probe-serverB.json
    python3 dualtor_host_probe.py --compare probe-*.json

Run the identical command on a high-failure server and a low-failure
server, then compare. Nothing on any testbed and nothing in the repository
is modified; the probe builds and destroys its own scratch bridge.

ADO: https://msazure.visualstudio.com/One/_workitems/edit/39415272
"""

from __future__ import print_function

import argparse
import atexit
import glob
import json
import os
import platform
import subprocess
import sys
import time


SCRATCH_PREFIX = "dtprobe-"

_created_bridge = None
_sudo_prefix = []


def _cmd(argv):
    return _sudo_prefix + argv


def run(argv, stdin_data=None, check=True):
    """Run a command, returning (rc, stdout, stderr, duration_ms)."""
    started = time.time()
    proc = subprocess.Popen(
        _cmd(argv),
        stdin=subprocess.PIPE if stdin_data is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate(
        stdin_data.encode("utf-8") if stdin_data is not None else None
    )
    duration_ms = (time.time() - started) * 1000.0
    out = out.decode("utf-8", "replace")
    err = err.decode("utf-8", "replace")
    if check and proc.returncode != 0:
        raise RuntimeError(
            "command failed rc={0}\n  cmd: {1}\n  stderr: {2}".format(
                proc.returncode, " ".join(_cmd(argv)), err.strip()
            )
        )
    return proc.returncode, out, err, duration_ms


def stats(samples):
    """Return count/min/p50/p95/p99/max/mean for a list of millisecond floats."""
    if not samples:
        return {}
    ordered = sorted(samples)
    n = len(ordered)

    def pct(p):
        idx = int(round(p / 100.0 * n + 0.5)) - 1
        return ordered[min(max(idx, 0), n - 1)]

    return {
        "count": n,
        "min_ms": round(ordered[0], 2),
        "p50_ms": round(pct(50), 2),
        "p95_ms": round(pct(95), 2),
        "p99_ms": round(pct(99), 2),
        "max_ms": round(ordered[-1], 2),
        "mean_ms": round(sum(ordered) / n, 2),
    }


def host_context():
    """Collect the host attributes that plausibly explain the 49x spread."""
    ctx = {
        "hostname": platform.node(),
        "kernel": platform.release(),
    }

    try:
        _, out, _, _ = run(["lscpu"], check=False)
        fields = {}
        for line in out.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                fields[key.strip()] = value.strip()
        ctx["cpu_model"] = fields.get("Model name")
        ctx["cpu_logical"] = fields.get("CPU(s)")
        ctx["cpu_mhz_max"] = fields.get("CPU max MHz")
        ctx["l3_cache"] = fields.get("L3 cache")
        mitigations = {
            k[len("Vulnerability "):]: v
            for k, v in fields.items()
            if k.startswith("Vulnerability ")
        }
        ctx["mitigations"] = mitigations
        # Active mitigations tax the syscall/VM-exit path, which is exactly
        # what process spawn stresses.
        ctx["mitigations_active"] = sum(
            1 for v in mitigations.values() if "Mitigation" in v
        )
        ctx["mitigations_not_affected"] = sum(
            1 for v in mitigations.values() if "Not affected" in v
        )
    except Exception as exc:  # noqa: BLE001 - diagnostics must never abort the run
        ctx["lscpu_error"] = str(exc)

    try:
        _, out, _, _ = run(["ovs-vsctl", "--version"], check=False)
        lines = out.splitlines()
        ctx["ovs_version"] = lines[0].strip() if lines else ""
    except Exception as exc:  # noqa: BLE001
        ctx["ovs_version_error"] = str(exc)

    try:
        ctx["loadavg"] = open("/proc/loadavg").read().split()[:3]
    except Exception:  # noqa: BLE001
        pass

    try:
        ctx["nproc_online"] = os.sysconf("SC_NPROCESSORS_ONLN")
    except Exception:  # noqa: BLE001
        pass

    try:
        _, out, _, _ = run(["ovs-vsctl", "list-br"], check=False)
        bridges = [b for b in out.split() if b]
        ctx["total_bridges"] = len(bridges)
        # Live mux bridges indicate how much real DualToR work this host carries.
        ctx["live_mux_bridges"] = len([b for b in bridges if b.startswith("mbr-")])
    except Exception:  # noqa: BLE001
        pass

    return ctx


def cleanup_bridge():
    global _created_bridge
    if not _created_bridge:
        return
    name = _created_bridge
    _created_bridge = None
    run(["ovs-vsctl", "--if-exists", "del-br", name], check=False)
    print("cleaned up scratch bridge {0}".format(name))


def setup_bridge(nports):
    """Create an isolated scratch bridge with nports + 1 internal ports.

    The name cannot match mux_simulator's `mbr-<...>-<vm_set>-<idx>` scan
    pattern, so a running simulator will never adopt this bridge.
    """
    global _created_bridge

    name = "{0}{1}".format(SCRATCH_PREFIX, os.getpid())
    if len(name) > 15:
        name = name[:15]

    _, out, _, _ = run(["ovs-vsctl", "list-br"], check=False)
    if name in out.split():
        raise RuntimeError("scratch bridge {0} already exists".format(name))

    run(["ovs-vsctl", "add-br", name])
    _created_bridge = name
    atexit.register(cleanup_bridge)

    sink = "dtps{0}".format(os.getpid() % 100000)
    run(["ovs-vsctl", "add-port", name, sink,
         "--", "set", "interface", sink, "type=internal"])

    ports = []
    for i in range(nports):
        port = "dtp{0}x{1}".format(os.getpid() % 1000, i)
        if len(port) > 15:
            raise RuntimeError("generated port name too long: {0}".format(port))
        run(["ovs-vsctl", "add-port", name, port,
             "--", "set", "interface", port, "type=internal"])
        ports.append(port)

    return name, sink, ports


def probe_spawn(iterations):
    """Pure fork/exec cost. `ovs-ofctl --version` never contacts the daemon.

    This is the cleanest host-capability signal available: it isolates
    process creation from anything OVS does.
    """
    return [run(["ovs-ofctl", "--version"], check=False)[3]
            for _ in range(iterations)]


def probe_ovs_read(bridge, iterations):
    """One trivial OVS read per call (dump-flows on a near-empty bridge)."""
    return [run(["ovs-ofctl", "--names", "dump-flows", bridge], check=False)[3]
            for _ in range(iterations)]


def probe_ovs_write(bridge, port, sink, iterations):
    """One trivial OVS write per call (add-flow then del-flows)."""
    samples = []
    for _ in range(iterations):
        _, _, _, ms_add = run(
            ["ovs-ofctl", "--names", "add-flow", bridge,
             'in_port="{0}",actions=output:"{1}"'.format(port, sink)],
            check=False)
        _, _, _, ms_del = run(
            ["ovs-ofctl", "--names", "del-flows", bridge,
             'in_port="{0}"'.format(port)],
            check=False)
        samples.append(ms_add)
        samples.append(ms_del)
    return samples


def capability_score(spawn, ovs_write):
    """Lower is better. Median cost of one spawn plus one trivial OVS write."""
    if not spawn or not ovs_write:
        return None
    return round(spawn.get("p50_ms", 0) + ovs_write.get("p50_ms", 0), 2)


def do_probe(args):
    global _sudo_prefix

    if sys.platform.startswith("win"):
        print("This probe must run on the Linux test server that hosts the mux "
              "simulator, not on a workstation.", file=sys.stderr)
        return 2

    if not args.no_sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
        _sudo_prefix = ["sudo"]

    results = {
        "schema": "dualtor-host-probe/1",
        "collected_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_context(),
        "measurements": {},
    }
    host = results["host"]

    print("=" * 70)
    print("DualToR test-server capability probe")
    print("  host        : {0}".format(host.get("hostname")))
    print("  cpu         : {0}".format(host.get("cpu_model")))
    print("  logical cpus: {0}    L3: {1}".format(
        host.get("cpu_logical"), host.get("l3_cache")))
    print("  spec-exec   : {0} mitigated / {1} not affected".format(
        host.get("mitigations_active"), host.get("mitigations_not_affected")))
    print("  ovs         : {0}".format(host.get("ovs_version")))
    print("  loadavg     : {0}".format(" ".join(host.get("loadavg", []))))
    print("  bridges     : {0} total, {1} live mux bridges".format(
        host.get("total_bridges"), host.get("live_mux_bridges")))
    print("=" * 70)

    print("\n[1/3] process spawn only (no OVS daemon contact)")
    spawn = stats(probe_spawn(args.iterations))
    results["measurements"]["spawn_only"] = spawn
    if spawn:
        print("      p50={p50_ms} ms   p95={p95_ms} ms   p99={p99_ms} ms".format(**spawn))

    print("\n[2/3] creating scratch bridge")
    bridge, sink, ports = setup_bridge(args.ports)
    print("      {0} with {1} ports".format(bridge, args.ports))

    print("\n[3/3] trivial OVS operations on the scratch bridge")
    ovs_read = stats(probe_ovs_read(bridge, args.iterations))
    ovs_write = stats(probe_ovs_write(bridge, ports[0], sink, args.iterations))
    results["measurements"]["ovs_read"] = ovs_read
    results["measurements"]["ovs_write"] = ovs_write
    if ovs_read:
        print("      read  p50={p50_ms} ms  p95={p95_ms} ms  p99={p99_ms} ms".format(
            **ovs_read))
    if ovs_write:
        print("      write p50={p50_ms} ms  p95={p95_ms} ms  p99={p99_ms} ms".format(
            **ovs_write))

    score = capability_score(spawn, ovs_write)
    results["measurements"]["capability_score_ms"] = score

    spawn_share = None
    if spawn and ovs_write and ovs_write.get("p50_ms"):
        spawn_share = round(spawn["p50_ms"] / ovs_write["p50_ms"] * 100.0, 1)
        results["measurements"]["spawn_share_of_write_pct"] = spawn_share

    print("\n" + "=" * 70)
    print("RESULT")
    print("  capability score (lower is better) : {0} ms".format(score))
    if spawn_share is not None:
        print("  spawn cost as share of one write   : {0}%".format(spawn_share))
    print("=" * 70)
    print("\nRun this on a high-failure server and a low-failure server, then:")
    print("  python3 {0} --compare 'probe-*.json'".format(
        os.path.basename(sys.argv[0])))

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(results, handle, indent=2, sort_keys=True)
        print("\nwrote {0}".format(args.json))

    return 0


def do_compare(patterns):
    """Render a cross-host comparison from previously written JSON files."""
    paths = []
    for pattern in patterns:
        paths.extend(sorted(glob.glob(pattern)))
    if not paths:
        print("no probe files matched", file=sys.stderr)
        return 1

    rows = []
    for path in paths:
        try:
            with open(path) as handle:
                data = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            print("skipping {0}: {1}".format(path, exc), file=sys.stderr)
            continue
        host = data.get("host", {})
        meas = data.get("measurements", {})
        rows.append({
            "host": host.get("hostname", path),
            "cpu": (host.get("cpu_model") or "")[:34],
            "mit": host.get("mitigations_active"),
            "spawn_p50": (meas.get("spawn_only") or {}).get("p50_ms"),
            "spawn_p95": (meas.get("spawn_only") or {}).get("p95_ms"),
            "write_p50": (meas.get("ovs_write") or {}).get("p50_ms"),
            "write_p99": (meas.get("ovs_write") or {}).get("p99_ms"),
            "score": meas.get("capability_score_ms"),
        })

    rows.sort(key=lambda r: (r["score"] is None, r["score"]))

    header = "{0:<22} {1:<34} {2:>4} {3:>10} {4:>10} {5:>10} {6:>10} {7:>9}".format(
        "host", "cpu", "mit", "spawn p50", "spawn p95", "write p50", "write p99", "score")
    print(header)
    print("-" * len(header))
    for r in rows:
        print("{0:<22} {1:<34} {2:>4} {3:>10} {4:>10} {5:>10} {6:>10} {7:>9}".format(
            str(r["host"])[:22], r["cpu"], str(r["mit"]),
            str(r["spawn_p50"]), str(r["spawn_p95"]),
            str(r["write_p50"]), str(r["write_p99"]), str(r["score"])))

    best = next((r for r in rows if r["score"]), None)
    worst = next((r for r in reversed(rows) if r["score"]), None)
    if best and worst and best is not worst and best["score"]:
        print("\nspread: {0:.1f}x between {1} and {2}".format(
            worst["score"] / best["score"], best["host"], worst["host"]))
        print("Place high fan-out DualToR topologies (120-port, 56-port) on the")
        print("hosts at the top of this table.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Measure DualToR test-server capability for placement decisions.")
    parser.add_argument("--ports", type=int, default=4,
                        help="scratch ports to create (small; this is not a load test)")
    parser.add_argument("--iterations", type=int, default=50,
                        help="samples per measurement")
    parser.add_argument("--json", help="write results to this path")
    parser.add_argument("--no-sudo", action="store_true",
                        help="do not prefix commands with sudo")
    parser.add_argument("--compare", nargs="+", metavar="GLOB",
                        help="compare previously written probe JSON files and exit")
    args = parser.parse_args()

    if args.compare:
        return do_compare(args.compare)
    return do_probe(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        cleanup_bridge()
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        cleanup_bridge()
        print("ERROR: {0}".format(exc), file=sys.stderr)
        sys.exit(1)
