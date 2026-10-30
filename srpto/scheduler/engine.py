"""
srpto.scheduler.engine
=======================
Parallel scheduler engine — the heart of SRPTO.

Mirrors the architecture of Eka's _run_spytest_execution() (main.py 6678-7200)
but runs scripts via subprocess (spytest or pytest) instead of a remote SSH
worker.  The DUT pool and lock logic is fully reused from
srpto.lock_manager.dut_lock.DUTPool.

Execution model (same as Eka):
  ┌─────────────────────────────────────────────────┐
  │  ONE call to engine.run(scripts)                │
  │   ↓                                             │
  │  spawn ONE worker thread per script             │
  │   ↓                                             │
  │  each worker calls pool.acquire() ─── BLOCKS    │
  │  until DUTs are free                            │
  │   ↓                                             │
  │  launches spytest/pytest subprocess             │
  │   ↓                                             │
  │  calls pool.release() when done                 │
  └─────────────────────────────────────────────────┘

New SRPTO concepts vs Eka:
  * Works locally (subprocess) instead of remote SSH
  * Supports both spytest and pytest (sonic-mgmt) invocation styles
  * Resource-map driven (no topology canvas — uses YAML or inline markers)
  * JSON status stream on stdout (replaces WebSocket / _exec_queue_state)
  * Plugin hook system: pre_script / post_script / on_conflict
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from srpto.lock_manager.dut_lock import DUTPool, ResourceRequirement, LockTier
from srpto.resource_tagger.tagger import ResourceTagger, parse_link_requirements
from srpto.scheduler.conflict import ConflictDetector

logger = logging.getLogger("srpto.scheduler")


# ---------------------------------------------------------------------------
# Script result
# ---------------------------------------------------------------------------

@dataclass
class ScriptResult:
    script_path: str
    status: str          # queued | waiting | running | done | failed | cancelled
    duts_allocated: List[str] = field(default_factory=list)
    return_code: Optional[int] = None
    log_path: Optional[str] = None
    duration_s: float = 0.0
    error: str = ""


# ---------------------------------------------------------------------------
# Scheduler configuration
# ---------------------------------------------------------------------------

@dataclass
class SchedulerConfig:
    # Testbed YAML (sonic-mgmt / spytest style)
    testbed_path: str = ""
    # Resource map YAML (srpto resource declarations)
    resource_map_path: str = ""
    # Logs output directory
    logs_dir: str = "./srpto_logs"
    # Maximum parallel workers
    max_workers: int = 16
    # DUT acquire timeout in seconds (0 = wait forever, matches Eka default)
    acquire_timeout: float = 0.0
    # Poll interval for DUT pool (seconds, default matches Eka)
    poll_interval: float = 5.0
    # Invocation mode: "spytest" or "pytest"
    mode: str = "spytest"
    # Extra CLI args passed to every script invocation
    extra_args: List[str] = field(default_factory=list)
    # spytest binary path (resolved automatically if empty)
    spytest_bin: str = ""
    # pytest binary path
    pytest_bin: str = "pytest"
    # Status callback: receives ScriptResult on every status change
    on_status_change: Optional[Callable[[ScriptResult], None]] = None
    # Enable dry-run (resolve allocations only, no subprocess)
    dry_run: bool = False
    # Optional shell command run on each allocated DUT after its test finishes.
    # Prevents "dirty DUT" failures when the next test inherits stale state
    # (e.g. stale BGP routes, ACLs, VLANs from a previous parallel session).
    # The command receives each DUT name as a positional arg.
    # Example: "ssh admin@{dut} sudo config reload -y"
    # Leave empty to skip scrub (default — matches current sequential behaviour).
    dut_scrub_cmd: str = ""
    # Emit the raw {"type":"queue_state",...} JSON line on every status change
    # (for CI/UI consumers that parse it). Default False — a human watching
    # the terminal gets a clean one-line pool snapshot instead of a repeated
    # JSON dump; the [QUEUE]/[ALLOC]/[RUNNING]/[DONE] log lines already say
    # what changed and why.
    stream_json: bool = False


# ---------------------------------------------------------------------------
# Testbed parser
# ---------------------------------------------------------------------------

def _parse_testbed(
    testbed_path: str,
) -> Tuple[List[str], Dict[Tuple[str, str], int], Optional[str], Dict[str, int]]:
    """
    Parse a sonic-mgmt / spytest testbed YAML and return:
      (dut_names, topology_connections, ptf_host, tgen_link_counts)

    Supports spytest v1 (links: list), v1 legacy (topo.properties.peers), and
    v2 "2.0" testbed formats (topology: interfaces/EndDevice dict, and the
    params.topo link-count map, e.g. {D1D2: 1, D1T1: 2, ...}).

    tgen_link_counts maps a DUT name to how many links it has to something
    that is NOT a DUT in this testbed (i.e. a traffic generator / T1 host) —
    used for topology-feasibility checks. A script needing "D1T1:2" cannot
    be satisfied by a testbed with no such device, no matter which DUTs are
    free.
    """
    if not testbed_path or not os.path.exists(testbed_path):
        logger.warning("[Testbed] File not found: %s — using empty testbed", testbed_path)
        return [], {}, None, {}

    with open(testbed_path) as f:
        tb = yaml.safe_load(f) or {}

    dut_names = list(tb.get("devices", {}).keys())
    dut_name_set = set(dut_names)
    ptf_host = tb.get("ptf_host") or tb.get("ptf")
    topology_connections: Dict[Tuple[str, str], int] = {}
    tgen_link_counts: Dict[str, int] = {}

    # Parse topology links (spytest v1 format: links section)
    links_section = tb.get("links", [])
    for link in links_section:
        # link: {endpoints: [dut1:eth0, dut2:eth1]} or similar
        if isinstance(link, dict):
            eps = link.get("endpoints", [])
            if len(eps) >= 2:
                dA = eps[0].split(":")[0]
                dB = eps[1].split(":")[0]
                if dA in dut_name_set and dB in dut_name_set:
                    key = (dA, dB)
                    topology_connections[key] = topology_connections.get(key, 0) + 1
                else:
                    tgen_end = dA if dA not in dut_name_set else dB
                    dut_end = dB if dA not in dut_name_set else dA
                    if dut_end in dut_name_set:
                        tgen_link_counts[dut_end] = tgen_link_counts.get(dut_end, 0) + 1

    # Parse legacy sonic-mgmt format: topo section with port-channel / interface maps
    topo_legacy = tb.get("topo", {})
    if topo_legacy and not links_section:
        # Best-effort: extract DUT pairs from port_channel_config or interface_config
        for dut, iface_map in topo_legacy.get("properties", {}).items():
            for peer in iface_map.get("peers", {}).keys():
                if dut in dut_name_set and peer in dut_name_set:
                    key = (dut, peer)
                    topology_connections[key] = topology_connections.get(key, 0) + 1
                elif dut in dut_name_set:
                    tgen_link_counts[dut] = tgen_link_counts.get(dut, 0) + 1

    # Parse v2 "params.topo" link-count map: {"D1D2": 1, "D1T1": 2, ...}
    # This is the format master_testbed.yaml (and other v2 spytest testbeds)
    # actually use — previously unrecognized, so topology_connections was
    # always empty for these testbeds and topology-aware allocation never ran.
    params = tb.get("params", {}) or {}
    topo_map = params.get("topo", {}) or {}
    for key, count in topo_map.items():
        labels = re.findall(r'[A-Za-z]+\d+', str(key))
        if len(labels) != 2:
            continue
        a, b = labels
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 1
        a_is_dut = a in dut_name_set
        b_is_dut = b in dut_name_set
        if a_is_dut and b_is_dut:
            k = (a, b)
            topology_connections[k] = topology_connections.get(k, 0) + count
        elif a_is_dut:
            tgen_link_counts[a] = tgen_link_counts.get(a, 0) + count
        elif b_is_dut:
            tgen_link_counts[b] = tgen_link_counts.get(b, 0) + count

    # Parse v2 "topology:" dict (interfaces / EndDevice), only when params.topo
    # didn't already give us counts — avoids double-counting the same links.
    topo_v2 = tb.get("topology", {}) or {}
    if topo_v2 and not topo_map:
        for dut, info in topo_v2.items():
            if dut not in dut_name_set:
                continue
            for _iface, ifinfo in (info.get("interfaces", {}) or {}).items():
                peer = ifinfo.get("EndDevice", "")
                if not peer:
                    continue
                if peer in dut_name_set:
                    key = (dut, peer)
                    topology_connections[key] = topology_connections.get(key, 0) + 1
                else:
                    tgen_link_counts[dut] = tgen_link_counts.get(dut, 0) + 1

    logger.info(
        "[Testbed] Parsed %d DUT(s): %s | PTF: %s | Links: %d | TGEN links: %s",
        len(dut_names), dut_names, ptf_host, len(topology_connections), tgen_link_counts
    )
    return dut_names, topology_connections, ptf_host, tgen_link_counts


# ---------------------------------------------------------------------------
# Pre-flight topology feasibility check
# ---------------------------------------------------------------------------

def _check_topology_feasible(
    req: ResourceRequirement,
    all_dut_names: List[str],
    topology_connections: Dict[Tuple[str, str], int],
    tgen_link_counts: Dict[str, int],
) -> Tuple[bool, str]:
    """
    Decide, once, whether req's topology requirement can EVER be satisfied by
    this testbed — independent of which DUTs happen to be busy right now.

    Unlike DUTPool._find_duts_matching_topology (which only searches among
    currently-free DUTs, and only checks DUT-DUT link_requirements), this
    searches the FULL DUT inventory and also checks tgen_link_requirements
    (a traffic-generator link count per DUT role, e.g. "D1T1:2" — this isn't
    a DUT at all, so DUTPool has no concept of it).

    A script whose requirement can never be met (missing TGEN device, or not
    enough physical links between any combination of DUTs) should be skipped
    up front rather than queued — it would otherwise sit waiting, or worse,
    get DUTs assigned and fail deep inside spytest's own
    ensure_min_topology() check, after the lock was already held.

    Returns (True, "") if satisfiable, else (False, reason).
    """
    if req.dut_count > len(all_dut_names):
        return False, (
            f"needs {req.dut_count} DUT(s), testbed only has {len(all_dut_names)}"
        )

    if not req.link_requirements and not req.tgen_link_requirements:
        return True, ""

    from itertools import combinations, permutations

    for combo in combinations(all_dut_names, req.dut_count):
        for perm in permutations(combo):
            role_map = {f"D{i + 1}": name for i, name in enumerate(perm)}
            ok = True
            for (rA, rB), min_links in req.link_requirements.items():
                dA, dB = role_map.get(rA), role_map.get(rB)
                if not dA or not dB:
                    ok = False
                    break
                actual = (
                    topology_connections.get((dA, dB), 0)
                    or topology_connections.get((dB, dA), 0)
                )
                if actual < min_links:
                    ok = False
                    break
            if ok:
                for rA, min_links in req.tgen_link_requirements.items():
                    dA = role_map.get(rA)
                    if not dA or tgen_link_counts.get(dA, 0) < min_links:
                        ok = False
                        break
            if ok:
                return True, ""

    # Nothing satisfied — build a concrete reason (best combo found: the one
    # covering the most DUT-DUT requirements, for a readable message).
    reasons = []
    for (rA, rB), min_links in req.link_requirements.items():
        best = max(
            (
                topology_connections.get((dA, dB), 0) or topology_connections.get((dB, dA), 0)
                for dA in all_dut_names for dB in all_dut_names if dA != dB
            ),
            default=0,
        )
        if best < min_links:
            reasons.append(f"{rA}{rB}:{min_links} (best available anywhere: {best})")
    for rA, min_links in req.tgen_link_requirements.items():
        best = max(tgen_link_counts.values(), default=0)
        if best < min_links:
            if not tgen_link_counts:
                reasons.append(f"{rA}T1:{min_links} (no TGEN/T1 device in testbed)")
            else:
                reasons.append(f"{rA}T1:{min_links} (best available anywhere: {best})")
    if not reasons:
        reasons.append("no combination of DUTs in the testbed satisfies all link requirements together")
    return False, "; ".join(reasons)


# ---------------------------------------------------------------------------
# Scarcity-aware DUT scoring
# ---------------------------------------------------------------------------
#
# See srpto/docs/scarcity_aware_allocation.md for the worked example and the
# full design writeup. One-paragraph summary of the problem this solves:
#
# DUTPool._find_duts_matching_topology() used to return the FIRST DUT
# combination (in itertools.combinations() order) that satisfies a script's
# link_requirements. That's fine when only one script needs a constrained
# pairing, but when several scripts in the same run could each be satisfied
# by MULTIPLE pairings, "first match wins" can hand a flexible script the
# one pairing that's the ONLY option for a stricter script later in the
# queue — forcing that stricter script to wait on a DUT it could never have
# avoided needing, for no reason, when the flexible script had other DUTs
# it could just as well have used instead.

def _enumerate_valid_combos(
    req: ResourceRequirement,
    all_dut_names: List[str],
    topology_connections: Dict[Tuple[str, str], int],
    tgen_link_counts: Dict[str, int],
) -> List[Tuple[str, ...]]:
    """
    Every distinct physical DUT combination (order-independent) that could
    EVER satisfy req's dut_count + link_requirements + tgen_link_requirements,
    searched against the FULL testbed inventory — not just currently-free
    DUTs. Used only for scoring (see _compute_dut_scarcity), never for a
    live allocation decision.

    Returns [] for a requirement with no link/tgen constraint at all — a
    plain "give me N DUTs" request has no meaningfully "scarce" combination
    (any N free DUTs work), so it contributes nothing to scarcity scoring.
    """
    if req.dut_count > len(all_dut_names):
        return []
    if not req.link_requirements and not req.tgen_link_requirements:
        return []

    from itertools import combinations, permutations

    valid: List[Tuple[str, ...]] = []
    seen: Set[Tuple[str, ...]] = set()
    for combo in combinations(all_dut_names, req.dut_count):
        key = tuple(sorted(combo))
        if key in seen:
            continue
        for perm in permutations(combo):
            role_map = {f"D{i + 1}": name for i, name in enumerate(perm)}
            ok = True
            for (rA, rB), min_links in req.link_requirements.items():
                dA, dB = role_map.get(rA), role_map.get(rB)
                if not dA or not dB:
                    ok = False
                    break
                actual = (
                    topology_connections.get((dA, dB), 0)
                    or topology_connections.get((dB, dA), 0)
                )
                if actual < min_links:
                    ok = False
                    break
            if ok:
                for rA, min_links in req.tgen_link_requirements.items():
                    dA = role_map.get(rA)
                    if not dA or tgen_link_counts.get(dA, 0) < min_links:
                        ok = False
                        break
            if ok:
                valid.append(combo)
                seen.add(key)
                break  # one valid permutation is enough to mark this combo valid
    return valid


def _compute_dut_scarcity(
    requirements: Dict[str, ResourceRequirement],
    all_dut_names: List[str],
    topology_connections: Dict[Tuple[str, str], int],
    tgen_link_counts: Dict[str, int],
) -> Tuple[Dict[str, float], Dict[str, Dict[str, float]]]:
    """
    Score every DUT by how "precious" it is across the WHOLE batch of
    scripts in this run. A script with only one valid combination (e.g. the
    only pair in the testbed with enough links) contributes a full 1.0 to
    each DUT in that combination; a script with several equally-valid
    combinations spreads 1.0 across them (1/N each), so no single option
    looks artificially scarce just because one script could use it.

    Computed ONCE per run, from the full known script batch — but each
    script's own contribution is handed back separately
    (per_script_contribution[script_name][dut] = weight) so the pool can
    RETIRE it the instant that script is actually allocated (see
    DUTPool._try_allocate's commit step). A script that has already
    committed to a specific combo is no longer "pending demand" — leaving
    its weight in place would needlessly steer later, still-waiting
    scripts away from DUTs that script is never going to reconsider. This
    makes the scores live across the run without ever recomputing the
    combinatorial search — retiring is an O(1) subtraction, not a
    re-enumeration.

    requirements must be keyed by the same script-name identifier the
    scheduler later passes to DUTPool.acquire() (os.path.basename(path)),
    so the pool can look up and retire the right contribution by name.
    """
    scores: Dict[str, float] = {name: 0.0 for name in all_dut_names}
    per_script: Dict[str, Dict[str, float]] = {}
    for script_name, req in requirements.items():
        combos = _enumerate_valid_combos(req, all_dut_names, topology_connections, tgen_link_counts)
        if not combos:
            continue
        weight = 1.0 / len(combos)
        contrib: Dict[str, float] = {}
        for combo in combos:
            for dut in combo:
                scores[dut] = scores.get(dut, 0.0) + weight
                contrib[dut] = contrib.get(dut, 0.0) + weight
        per_script[script_name] = contrib
    return scores, per_script


# ---------------------------------------------------------------------------
# Subset testbed generator (mirrors Eka _create_subset_testbed)
# ---------------------------------------------------------------------------

def _create_subset_testbed(testbed_config: dict, allocated_duts: List[str]) -> dict:
    """
    Build a minimal testbed YAML containing only the allocated DUTs.
    Direct port of Eka _create_subset_testbed (main.py 3517-3551).

    Handles both spytest v1 (links list) and v2 (topology dict + params.topo dict).
    """
    import copy
    import re as _re
    allocated_set = set(allocated_duts)
    subset = copy.deepcopy(testbed_config)

    # ── 1. Filter devices: section ────────────────────────────────────────────
    all_devices = subset.get("devices", {})
    for dut in list(all_devices.keys()):
        if dut not in allocated_set:
            del all_devices[dut]

    # ── 2. Filter links: list (spytest v1 format) ─────────────────────────────
    if "links" in subset:
        subset["links"] = [
            lnk for lnk in subset["links"]
            if all(
                ep.split(":")[0] in allocated_set
                for ep in lnk.get("endpoints", [])
            )
        ]

    # ── 3. Filter topology: dict (spytest v2 format) ──────────────────────────
    # topology: { D1: { interfaces: { Eth0: {EndDevice: D2, ...} } }, D2: {...} }
    # Keep only DUTs in allocated_set; within each DUT prune interfaces
    # whose EndDevice is not in allocated_set.
    if "topology" in subset:
        topo = subset["topology"]
        for dut in list(topo.keys()):
            if dut not in allocated_set:
                del topo[dut]
            else:
                ifaces = topo[dut].get("interfaces", {})
                for iface in list(ifaces.keys()):
                    end_device = ifaces[iface].get("EndDevice", "")
                    if end_device not in allocated_set:
                        del ifaces[iface]

    # ── 4. Filter params.topo dict (spytest v2 link-count map) ───────────────
    # params.topo: { D1D2: 1, D1D3: 1, D2D3: 2, ... }
    # Keep only pairs where both DUT labels appear in allocated_set.
    params = subset.get("params", {})
    if "topo" in params:
        topo_map = params["topo"]
        for key in list(topo_map.keys()):
            dut_labels = _re.findall(r'D\d+', key)
            if not all(lbl in allocated_set for lbl in dut_labels):
                del topo_map[key]

    return subset


# ---------------------------------------------------------------------------
# Script invoker
# ---------------------------------------------------------------------------

def _build_command(
    cfg: SchedulerConfig,
    script_path: str,
    subset_testbed_path: str,
    log_dir: str,
) -> List[str]:
    """Build the subprocess command for a single script.

    All paths are converted to absolute so they resolve correctly even when
    SpyTest is launched with cwd=workspace (the per-script isolated directory).
    """
    # Resolve all paths to absolute — SpyTest runs with cwd=workspace,
    # so any relative path (e.g. spytest/tests/routing/test_*.py) would
    # fail with "file or directory not found" if not made absolute here.
    abs_script     = os.path.abspath(script_path)
    abs_testbed    = os.path.abspath(subset_testbed_path)
    abs_logs       = os.path.abspath(log_dir)

    if cfg.mode == "spytest":
        spy_bin = cfg.spytest_bin or _find_spytest_bin(script_path)
        abs_spy_bin = os.path.abspath(spy_bin)
        cmd = [
            sys.executable, abs_spy_bin,
            "--tryssh", "1",
            "--testbed", abs_testbed,
            abs_script,
            "--logs-path", abs_logs,
            "--get-tech-support", "none",
            "--syslog-check", "none",
        ]
    else:
        # pytest (sonic-mgmt community style)
        cmd = [
            cfg.pytest_bin,
            abs_script,
            "--testbed-file", abs_testbed,
            f"--log-file={os.path.join(abs_logs, 'pytest.log')}",
        ]
    cmd += cfg.extra_args
    return cmd


def _build_env(cfg: SchedulerConfig) -> Optional[Dict[str, str]]:
    """
    Build the subprocess environment for a script invocation.

    SpyTest's "--get-tech-support none" (always passed in spytest mode, see
    _build_command) only controls cfg.get_tech_support. It does NOT disable
    the separate on_cr_recover trigger in spytest/net.py's _try(): whenever a
    command needs a CR to recover its prompt, is_tech_support_onerror()
    checks the independent SPYTEST_TECH_SUPPORT_ONERROR env var (default
    includes "on_cr_recover") and — if it matches — runs a fresh
    "show techsupport" collection right there in the exception handler. If
    that collection itself times out (tech-support generation is slow on
    real hardware), it has no further retry and escalates straight to a
    fatal EnvFail, killing an otherwise-recoverable transient CR blip.
    Disable that trigger by default here, matching "--get-tech-support
    none"'s intent, unless the caller's own environment already sets it
    explicitly (respect an explicit user choice).
    """
    if cfg.mode != "spytest":
        return None
    if "SPYTEST_TECH_SUPPORT_ONERROR" in os.environ:
        return None
    env = dict(os.environ)
    env["SPYTEST_TECH_SUPPORT_ONERROR"] = ""
    return env


def _find_spytest_bin(script_path: str) -> str:
    """Walk up from script_path to find bin/spytest."""
    p = Path(script_path).resolve()
    for parent in p.parents:
        candidate = parent / "bin" / "spytest"
        if candidate.exists():
            return str(candidate)
    return "spytest"


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class ParallelScheduler:
    """
    SRPTO Parallel Scheduler.

    Usage:
        cfg = SchedulerConfig(testbed_path="sonic_t0.yaml", mode="pytest")
        scheduler = ParallelScheduler(cfg)
        results = scheduler.run([
            "tests/bgp/test_bgp_gr.py",
            "tests/acl/test_acl.py",
            "tests/snmp/test_snmp.py",
        ])
    """

    def __init__(self, cfg: SchedulerConfig):
        self.cfg = cfg
        self._stop_event = threading.Event()
        self._results: Dict[str, ScriptResult] = {}
        self._results_lock = threading.Lock()
        self._last_pool_sig: Optional[Tuple[Tuple[str, ...], Tuple[str, ...]]] = None

        # Parse testbed
        dut_names, topo_connections, ptf_host, tgen_link_counts = _parse_testbed(cfg.testbed_path)
        if not dut_names:
            logger.warning("[Scheduler] No DUTs in testbed — using synthetic slots")
            dut_names = ["Slot-1"]

        # Kept for the pre-flight topology-feasibility check (run()) — this is
        # the FULL testbed's DUT/link inventory, independent of what's
        # currently busy, so it can decide once, up front, whether a script's
        # requirement is even satisfiable, versus what DUTPool checks at
        # allocation time (which is about current availability).
        self._all_dut_names = list(dut_names)
        self._all_topology_connections = dict(topo_connections)
        self._tgen_link_counts = dict(tgen_link_counts)

        # DUT pool (Eka acquire_duts / release_duts)
        self._pool = DUTPool(
            dut_names=dut_names,
            ptf_host=ptf_host,
            topology_connections=topo_connections,
            poll_interval=cfg.poll_interval,
            max_wait_seconds=cfg.acquire_timeout,
        )
        self._pool.register_status_callback(self._on_pool_change)

        # Resource tagger
        self._tagger = ResourceTagger(cfg.resource_map_path)

        # Conflict detector
        self._conflict_detector = ConflictDetector()

        # Testbed config for subset generation
        self._testbed_config: dict = {}
        if cfg.testbed_path and os.path.exists(cfg.testbed_path):
            with open(cfg.testbed_path) as f:
                self._testbed_config = yaml.safe_load(f) or {}

        os.makedirs(cfg.logs_dir, exist_ok=True)
        logger.info("[Scheduler] Ready | DUTs: %s | Mode: %s", dut_names, cfg.mode)

    # ------------------------------------------------------------------
    # Public: run
    # ------------------------------------------------------------------

    def run(self, script_paths: List[str]) -> List[ScriptResult]:
        """
        Schedule and run all scripts in parallel.

        Returns a list of ScriptResult, one per script.

        Implementation mirrors Eka _run_spytest_execution():
          1. Analyse all scripts → ResourceRequirement
          2. Pre-flight conflict check
          3. Init queue state (_q_init equivalent)
          4. Spawn one thread per script
          5. Each thread: acquire DUTs → run subprocess → release DUTs
          6. Join all threads → return results
        """
        if not script_paths:
            logger.warning("[Scheduler] No scripts to run")
            return []

        logger.info(
            "[Scheduler] Starting %d script(s) in parallel | testbed: %s",
            len(script_paths), self.cfg.testbed_path
        )

        # ── 1. Resolve requirements for all scripts ───────────────────────────
        requirements: Dict[str, ResourceRequirement] = {}
        for path in script_paths:
            source = None
            try:
                with open(path) as f:
                    source = f.read()
            except Exception:
                pass
            requirements[path] = self._tagger.get_requirement(path, source)

        # ── 2. Pre-flight topology feasibility check ──────────────────────────
        # A script's DUT/link/TGEN requirement may be structurally unsatisfiable
        # by this testbed (not enough links anywhere, or no TGEN/T1 device at
        # all) no matter which DUTs are free. Catch that here — before
        # anything is queued or locked — instead of letting it wait forever or
        # burn a DUT allocation only to fail deep inside spytest's own
        # ensure_min_topology() check.
        runnable_paths = []
        for path in script_paths:
            ok, reason = _check_topology_feasible(
                requirements[path],
                self._all_dut_names,
                self._all_topology_connections,
                self._tgen_link_counts,
            )
            if ok:
                runnable_paths.append(path)
            else:
                sname = os.path.basename(path)
                logger.warning(
                    "[Scheduler] Skipping %s — insufficient topology: %s", sname, reason
                )
                with self._results_lock:
                    self._results[path] = ScriptResult(
                        script_path=path, status="skipped",
                        error=f"insufficient topology: {reason}",
                    )
        script_paths = runnable_paths

        # ── 2b. Scarcity-aware DUT scoring ─────────────────────────────────────
        # Computed once, from the full runnable batch, before any DUT is
        # touched — see _compute_dut_scarcity for why, and
        # srpto/docs/scarcity_aware_allocation.md for the worked example.
        # Scripts with no link/tgen requirement (plain "give me N DUTs")
        # contribute nothing and are unaffected by this. Keyed by basename
        # (sname) — the same identifier _run_one_script passes to
        # pool.acquire() — so the pool can retire each script's contribution
        # by name the moment it's allocated.
        dut_scarcity, scarcity_contributions = _compute_dut_scarcity(
            {os.path.basename(p): requirements[p] for p in script_paths},
            self._all_dut_names,
            self._all_topology_connections,
            self._tgen_link_counts,
        )
        self._pool.set_scarcity_scores(dut_scarcity, scarcity_contributions)

        # ── 3. Pre-flight conflict check ─────────────────────────────────────
        runnable_requirements = {p: requirements[p] for p in script_paths}
        conflicts = self._conflict_detector.check_all(runnable_requirements)
        if conflicts:
            logger.warning("[Scheduler] Pre-flight conflicts detected:")
            for c in conflicts:
                logger.warning("  %s", c)

        # ── 4. Init result slots (mirrors Eka _q_init) ────────────────────────
        with self._results_lock:
            for path in script_paths:
                self._results[path] = ScriptResult(
                    script_path=path, status="queued"
                )
        self._emit_queue_state()

        if not script_paths:
            logger.warning("[Scheduler] No runnable scripts after topology feasibility check")
            results = list(self._results.values())
            self._print_summary(results, 0.0)
            return results

        # ── 5. Spawn workers ─────────────────────────────────────────────────
        t_start = time.time()
        with ThreadPoolExecutor(
            max_workers=min(len(script_paths), self.cfg.max_workers),
            thread_name_prefix="srpto-worker"
        ) as executor:
            futures = {
                executor.submit(
                    self._run_one_script, path, requirements[path], idx
                ): path
                for idx, path in enumerate(script_paths)
            }
            for future in as_completed(futures):
                path = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error("[Scheduler] Worker exception for %s: %s", path, e)
                    with self._results_lock:
                        r = self._results[path]
                        r.status = "failed"
                        r.error = str(e)

        total = time.time() - t_start
        results = list(self._results.values())
        passed = sum(1 for r in results if r.status == "done")
        failed = sum(1 for r in results if r.status == "failed")
        skipped = sum(1 for r in results if r.status == "skipped")
        logger.info(
            "[Scheduler] All done in %.1fs | passed=%d failed=%d skipped=%d cancelled=%d",
            total, passed, failed, skipped, len(results) - passed - failed - skipped
        )
        self._print_summary(results, total)
        return results

    def stop(self):
        """Signal all workers to stop (mirrors Eka _is_exec_cancelled)."""
        self._stop_event.set()
        logger.info("[Scheduler] Stop signal sent")

    # ------------------------------------------------------------------
    # Internal: per-script worker (mirrors Eka run_one_script)
    # ------------------------------------------------------------------

    def _run_one_script(
        self, script_path: str, req: ResourceRequirement, slot_idx: int
    ):
        """
        Single script worker thread.

        Flow mirrors Eka run_one_script (main.py 6941-7100):
          1. acquire_duts() — blocks until DUTs available
          2. Create subset testbed YAML
          3. Launch spytest / pytest subprocess
          4. Stream log tail
          5. release_duts()
        """
        sname = os.path.basename(script_path)
        self._update_status(script_path, "waiting")
        # Register this request's DUT count for anti-starvation fairness.
        # The pool won't let smaller requests starve a large pending request.
        self._pool.register_pending(req.dut_count)
        logger.info(
            "[QUEUE][%s] Waiting for %d DUT(s) (exclusive=%s, ptf=%s)",
            sname, req.dut_count, req.topology_exclusive, req.ptf_required
        )

        allocated = []
        t0 = time.time()
        pending_unregistered = False

        try:
            # ── acquire_duts (Eka equivalent) ─────────────────────────────────
            allocated = self._pool.acquire(req, sname, self._stop_event)
            # Unregister as soon as we stop waiting — either we got our DUTs
            # or we gave up. Doing this here (rather than only in `finally`,
            # after the whole subprocess run) matters for the anti-starvation
            # guard in DUTPool._try_allocate: it must stop counting this
            # script's dut_count as "pending" once it is actually running,
            # otherwise it keeps holding back other requests' allocation
            # decisions for the entire runtime of this script instead of just
            # its wait time.
            self._pool.unregister_pending(req.dut_count)
            pending_unregistered = True
            if allocated is None:
                self._update_status(script_path, "cancelled",
                                    error="Timed out / stopped waiting for DUTs")
                return

            self._update_status(script_path, "running", duts=allocated)
            logger.info("[ALLOC][%s] → DUT(s): %s", sname, allocated)

            if self.cfg.dry_run:
                logger.info("[DRY-RUN][%s] Would run on DUTs: %s", sname, allocated)
                time.sleep(0.1)
                self._update_status(script_path, "done", duts=allocated,
                                    duration=time.time() - t0)
                return

            # ── Create isolated workspace per script ──────────────────────────
            # Each script gets its own directory so SpyTest artifacts
            # (results.csv, spytest.html, syslog, pcaps) NEVER collide between
            # parallel sessions. This is the subprocess isolation boundary.
            ts = int(time.time())
            workspace = os.path.join(
                self.cfg.logs_dir, f"run_{sname}_{ts}"
            )
            os.makedirs(workspace, exist_ok=True)

            # ── Write subset testbed YAML into the workspace ──────────────────
            # *** SpyTestSessionBinder ***
            # SpyTest receives a testbed YAML that contains ONLY the DUTs
            # allocated to this script. It physically cannot see or touch busy
            # DUTs. This is what actually enforces DUT isolation — not just the
            # Python lock. Without this, all subprocesses would share the same
            # testbed topology and use whatever DUTs it provides.
            subset_cfg = _create_subset_testbed(self._testbed_config, allocated)
            subset_tb_path = os.path.join(workspace, "testbed_subset.yaml")
            with open(subset_tb_path, "w") as f:
                yaml.dump(subset_cfg, f, default_flow_style=False)

            # Write a human-readable allocation record for debugging
            with open(os.path.join(workspace, "srpto_allocation.txt"), "w") as f:
                f.write(f"Script   : {script_path}\n")
                f.write(f"DUTs     : {allocated}\n")
                f.write(f"Testbed  : {self.cfg.testbed_path}\n")
                f.write(f"Subset   : {subset_tb_path}\n")
                f.write(f"PTF      : {req.ptf_required}\n")
                f.write(f"Exclusive: {req.topology_exclusive}\n")
                f.write(f"Resources: {sorted(req.shared_resources)}\n")

            log_dir = os.path.join(workspace, "logs")
            os.makedirs(log_dir, exist_ok=True)

            # ── Launch subprocess ─────────────────────────────────────────────
            # subset_tb_path → SpyTest sees ONLY allocated DUTs
            # cwd=workspace  → all SpyTest output files stay in this dir
            cmd = _build_command(self.cfg, script_path, subset_tb_path, log_dir)
            log_file = os.path.join(log_dir, "stdout.log")
            logger.info("[RUN][%s] workspace: %s", sname, workspace)
            logger.info(
                "[RUN][%s] subset testbed: %s (DUTs: %s)",
                sname, subset_tb_path, allocated
            )
            logger.info("[RUN][%s] CMD: %s", sname, " ".join(cmd))

            proc_env = _build_env(self.cfg)
            rc = self._run_process(cmd, log_file, script_path, sname,
                                    cwd=workspace, env=proc_env)

            dur = time.time() - t0
            if self._stop_event.is_set() and rc != 0:
                self._update_status(script_path, "cancelled", duts=allocated,
                                    return_code=rc, log_path=log_dir, duration=dur)
            elif rc == 0:
                logger.info("[DONE][%s] ✓ in %.1fs", sname, dur)
                self._update_status(script_path, "done", duts=allocated,
                                    return_code=rc, log_path=log_dir, duration=dur)
            else:
                logger.error("[FAIL][%s] ✗ rc=%d in %.1fs", sname, rc, dur)
                self._update_status(script_path, "failed", duts=allocated,
                                    return_code=rc, log_path=log_dir, duration=dur,
                                    error=f"exit code {rc}")

        except Exception as e:
            logger.exception("[ERROR][%s] %s", sname, e)
            self._update_status(script_path, "failed", duts=allocated,
                                error=str(e), duration=time.time() - t0)
            raise
        finally:
            # Only unregister here if we never reached the acquire() return
            # above (e.g. acquire() itself raised) — otherwise this would
            # double-unregister and could wrongly clear a different, still-
            # pending script's larger dut_count out of the starvation guard.
            if not pending_unregistered:
                self._pool.unregister_pending(req.dut_count)
            # Optional: scrub DUTs before returning to pool to prevent
            # "dirty DUT" state from affecting the next parallel test.
            if allocated and self.cfg.dut_scrub_cmd:
                self._scrub_duts(allocated, sname)
            if allocated:
                self._pool.release(allocated, sname, req)

    def _scrub_duts(self, duts: List[str], sname: str):
        """
        Optional post-test DUT cleanup.

        Runs cfg.dut_scrub_cmd on each allocated DUT before releasing them
        back to the pool. This prevents a test from leaving stale BGP routes,
        ACL rules, VLAN configs, or PortChannel state that would cause the
        NEXT parallel test to fail on a "dirty" DUT.

        cfg.dut_scrub_cmd example:
            "ssh -o StrictHostKeyChecking=no admin@{dut} sudo config reload -y"

        The string {dut} is replaced with each DUT name. Failures are logged
        but do NOT prevent DUT release — a failed scrub is better than a
        deadlocked pool.
        """
        for dut in duts:
            cmd_str = self.cfg.dut_scrub_cmd.replace("{dut}", dut)
            try:
                logger.info("[SCRUB][%s] %s → %s", sname, dut, cmd_str)
                result = subprocess.run(
                    cmd_str, shell=True, timeout=120,
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    logger.warning(
                        "[SCRUB][%s] %s scrub failed (rc=%d): %s",
                        sname, dut, result.returncode, result.stderr[:300]
                    )
                else:
                    logger.info("[SCRUB][%s] %s scrubbed OK", sname, dut)
            except subprocess.TimeoutExpired:
                logger.warning("[SCRUB][%s] %s scrub timed out (120s)", sname, dut)
            except Exception as exc:
                logger.warning("[SCRUB][%s] %s scrub error: %s", sname, dut, exc)

    def _run_process(
        self, cmd: List[str], log_file: str, script_path: str, sname: str,
        cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
    ) -> int:
        """
        Launch a subprocess and tail its output.
        cwd= isolates all SpyTest output artifacts (results.csv, spytest.html,
        syslog, pcaps) to the per-script workspace directory.
        env=None inherits this process's environment unchanged (Popen default).
        """
        with open(log_file, "w") as lf:
            proc = subprocess.Popen(
                cmd,
                stdout=lf,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd,      # ← SpyTest writes all relative-path files here
                env=env,
            )

        last_pos = 0
        t_run_start = time.time()
        while True:
            time.sleep(10)

            # Check stop signal (mirrors Eka _is_exec_cancelled)
            if self._stop_event.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                logger.info("[%s] Killed by stop signal", sname)
                return -1

            # Stream log tail (mirrors Eka log_tail logic). The full tail
            # stays at debug (too noisy for a live terminal across several
            # parallel scripts) — but a one-line heartbeat at INFO means a
            # script that's been running for minutes doesn't look stuck:
            # without this, nothing was printed between "[RUN]" and
            # "[DONE]"/"[FAIL]" no matter how long the subprocess actually
            # took, because the only progress signal was at debug level.
            last_line = ""
            try:
                with open(log_file) as lf:
                    lf.seek(last_pos)
                    new_lines = lf.read()
                    last_pos = lf.tell()
                if new_lines.strip():
                    tail_lines = new_lines.strip().splitlines()
                    for line in tail_lines[-20:]:
                        logger.debug("[LOG][%s] %s", sname, line)
                    last_line = tail_lines[-1].strip()[:160]
            except Exception:
                pass

            elapsed = time.time() - t_run_start
            if last_line:
                logger.info("[RUNNING][%s] %.0fs elapsed | %s", sname, elapsed, last_line)
            else:
                logger.info("[RUNNING][%s] %.0fs elapsed", sname, elapsed)

            # Check if process finished
            rc = proc.poll()
            if rc is not None:
                return rc

    # ------------------------------------------------------------------
    # Status management (mirrors Eka _q_update_script / _exec_queue_state)
    # ------------------------------------------------------------------

    def _update_status(
        self, script_path: str, status: str,
        duts: Optional[List[str]] = None,
        return_code: Optional[int] = None,
        log_path: Optional[str] = None,
        duration: float = 0.0,
        error: str = "",
    ):
        with self._results_lock:
            r = self._results.get(script_path)
            if r:
                r.status = status
                if duts:
                    r.duts_allocated = duts
                if return_code is not None:
                    r.return_code = return_code
                if log_path:
                    r.log_path = log_path
                if duration:
                    r.duration_s = duration
                if error:
                    r.error = error

        if self.cfg.on_status_change:
            try:
                with self._results_lock:
                    r = self._results.get(script_path)
                if r:
                    self.cfg.on_status_change(r)
            except Exception:
                pass

        self._emit_queue_state()

    def _emit_queue_state(self):
        """
        Report the current queue/pool state.

        --stream-json (cfg.stream_json=True): print the raw
        {"type": "queue_state", ...} JSON line to stdout, unchanged — for
        CI/UI consumers that parse this stream.

        Default: no JSON dump at all. Printing that blob on every single
        status change (queued→waiting→running→done, per script) buried the
        already-readable [QUEUE]/[ALLOC]/[RUNNING]/[DONE] log lines under
        repeated machine-format noise. Instead, print one clean
        "[POOL] free: ... | busy: ..." line, and only when the actual
        free/busy sets changed since the last time — not on every status
        transition that didn't move a DUT.
        """
        with self._results_lock:
            scripts = [
                {
                    "name": os.path.basename(r.script_path),
                    "status": r.status,
                    "duts": r.duts_allocated,
                }
                for r in self._results.values()
            ]
        pool_status = self._pool.get_status()

        if self.cfg.stream_json:
            state = {
                "type": "queue_state",
                "scripts": scripts,
                "free_duts": pool_status["free_duts"],
                "busy_duts": pool_status["busy_duts"],
            }
            print(json.dumps(state), flush=True)
            return

        free = pool_status["free_duts"]
        busy = pool_status["busy_duts"]
        sig = (tuple(sorted(free)), tuple(sorted(busy)))
        if sig == self._last_pool_sig:
            return
        self._last_pool_sig = sig
        logger.info(
            "[POOL] free: %s | busy: %s",
            ", ".join(free) if free else "-",
            ", ".join(busy) if busy else "-",
        )

    def _on_pool_change(self, snap: dict):
        """Callback from DUTPool on any lock state change."""
        logger.debug("[Pool] Free: %s | Busy: %s", snap["free_duts"], snap["busy_duts"])

    def _print_summary(self, results: List[ScriptResult], total: float):
        """Print a human-readable execution summary (replaces Eka HTML report)."""
        print("\n" + "=" * 70)
        print(f"SRPTO Execution Summary  |  Total time: {total:.1f}s")
        print("=" * 70)
        print(f"{'Script':<40} {'Status':<12} {'DUTs':<20} {'Duration'}")
        print("-" * 70)
        for r in results:
            name = os.path.basename(r.script_path)[:39]
            duts = ",".join(r.duts_allocated) if r.duts_allocated else "-"
            dur = f"{r.duration_s:.1f}s"
            status_icon = {"done": "✓", "failed": "✗", "cancelled": "■", "skipped": "⊘"}.get(r.status, "?")
            print(f"{name:<40} {status_icon} {r.status:<10} {duts:<20} {dur}")
        print("=" * 70)
