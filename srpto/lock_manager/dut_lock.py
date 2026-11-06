"""
srpto.lock_manager.dut_lock
============================
Thread-safe DUT lock pool — direct port of Eka's acquire_duts / release_duts
logic from main.py (lines 6891-6938) extended to support:

  * PTF host locking
  * Exclusive topology lock (for config reload / reboot tests)
  * Shared-resource conflict detection (VLANs, port-channels)
  * Optional timeout so scripts never block forever

Eka original model (single-process threading):
  pool_lock  = threading.Lock()
  available_pool: list  — mutable shared state

SRPTO adds:
  LockTier.DEVICE    → per-DUT mutex (default, matches Eka behaviour)
  LockTier.PTF       → PTF host exclusive
  LockTier.TOPOLOGY  → whole-topology exclusive (warm-reboot, config reload)
"""

from __future__ import annotations

import re
import time
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("srpto.lock_manager")


# ---------------------------------------------------------------------------
# Lock tiers
# ---------------------------------------------------------------------------

class LockTier(Enum):
    DEVICE   = "device"    # per-DUT, same as Eka
    PTF      = "ptf"       # PTF host exclusive
    TOPOLOGY = "topology"  # whole topology exclusive (reboot / config reload)


# ---------------------------------------------------------------------------
# Resource descriptor
# ---------------------------------------------------------------------------

@dataclass
class ResourceRequirement:
    """What a single test script needs."""
    dut_count: int = 1
    dut_names: List[str] = field(default_factory=list)   # explicit names, or empty = any
    ptf_required: bool = False
    topology_exclusive: bool = False                      # config reload, reboot, warm-reboot
    shared_resources: Set[str] = field(default_factory=set)  # e.g. "vlan:100", "portchannel:Po1"
    link_requirements: Dict[Tuple[str, str], int] = field(default_factory=dict)
    # e.g. {("DUT1", "DUT2"): 2}  — matches Eka _find_duts_matching_topology input
    tgen_link_requirements: Dict[str, int] = field(default_factory=dict)
    # e.g. {"D1": 2, "D2": 2} from ensure_min_topology("D1T1:2", "D2T1:2") — minimum
    # traffic-generator (TGEN/T1) link count required on each DUT role. Not a DUT,
    # so it's checked separately from link_requirements (DUT-DUT pairs).


# ---------------------------------------------------------------------------
# Lock state
# ---------------------------------------------------------------------------

@dataclass
class DUTSlot:
    name: str          # testbed device name e.g. "sonic-dut-1"
    busy: bool = False
    held_by: Optional[str] = None   # script path holding the lock


# ---------------------------------------------------------------------------
# Main pool
# ---------------------------------------------------------------------------

class DUTPool:
    """
    Thread-safe DUT pool.

    Ported from Eka main.py:
      pool_lock = Lock()
      available_pool: list
      def acquire_duts(needed, link_requirements) -> list: ...
      def release_duts(duts_to_free) -> None: ...

    SRPTO extensions:
      * PTF exclusive lock
      * Topology exclusive lock
      * Timeout support
      * Conflict-aware allocation (shared resources)
    """

    def __init__(
        self,
        dut_names: List[str],
        ptf_host: Optional[str] = None,
        topology_connections: Optional[Dict[Tuple[str, str], int]] = None,
        poll_interval: float = 5.0,
        max_wait_seconds: float = 0.0,   # 0 = wait forever (Eka default)
    ):
        self._lock = threading.Lock()
        self._slots: Dict[str, DUTSlot] = {n: DUTSlot(name=n) for n in dut_names}
        self._ptf_host = ptf_host
        self._ptf_busy = False
        self._ptf_held_by: Optional[str] = None
        self._topo_exclusive = False
        self._topo_held_by: Optional[str] = None
        self._topology_connections: Dict[Tuple[str, str], int] = topology_connections or {}
        # shared resource → set of script names currently holding that resource
        self._shared_resources: Dict[str, Set[str]] = {}
        self._poll_interval = poll_interval
        self._max_wait = max_wait_seconds

        # DUT name -> scarcity score, fed in once by the scheduler before
        # scheduling starts (see engine._compute_dut_scarcity and
        # set_scarcity_scores below). Empty by default, which makes
        # _find_duts_matching_topology's scoring a no-op — every candidate
        # ties at 0.0 and the original lexicographic order wins, so this is
        # fully backward-compatible when nobody sets scores.
        self._dut_scarcity: Dict[str, float] = {}
        # script_name -> {dut: weight it contributed to _dut_scarcity}.
        # Consumed (popped) the instant that script is allocated — see the
        # "Commit allocation" step in _try_allocate — so the live scores
        # reflect only STILL-PENDING scripts' demand, without ever having to
        # redo the combinatorial search mid-run.
        self._scarcity_contributions: Dict[str, Dict[str, float]] = {}

        # Static physical adjacency, derived once from the testbed's real
        # links: dut -> set of DUTs it has at least one real link to. Used
        # only as a LIVE co-scheduling preference (see
        # _live_adjacency_penalty) — never a hard allocation constraint. On
        # a densely-meshed small lab almost every DUT touches several
        # others, so treating adjacency as a hard block would make most
        # parallelism impossible; it only steers AMONG already-valid
        # choices toward ones that don't currently border another script's
        # DUTs, reducing (not eliminating) the risk that one script's
        # config push bleeds across a shared cable into another script's
        # "isolated" DUT. See srpto/docs/adjacency_aware_allocation.md.
        self._adjacency: Dict[str, Set[str]] = {n: set() for n in dut_names}
        for (a, b) in (topology_connections or {}):
            if a in self._adjacency and b in self._adjacency:
                self._adjacency[a].add(b)
                self._adjacency[b].add(a)

        # Anti-starvation: track the largest DUT count currently pending.
        # While a 3-DUT test is waiting, the pool will not keep allocating
        # 1-DUT tests if that would leave < 3 DUTs free — preventing the
        # large test from ever getting its hardware.
        self._max_pending_dut_count: int = 0
        self._pending_count_lock = threading.Lock()

        # Status snapshot for the UI / websocket equivalent
        self._status_callbacks: List = []

        logger.info(
            "[DUTPool] Initialised with %d DUT(s): %s | PTF: %s | Topology links: %d",
            len(dut_names), dut_names, ptf_host, len(self._topology_connections)
        )

    # ------------------------------------------------------------------
    # Public: acquire / release  (mirrors Eka acquire_duts / release_duts)
    # ------------------------------------------------------------------

    def acquire(
        self,
        req: ResourceRequirement,
        script_name: str,
        stop_event: Optional[threading.Event] = None,
        poll_interval: Optional[float] = None,
    ) -> Optional[List[str]]:
        """
        Block until the requested resources are free and atomically grab them.

        Returns the list of allocated DUT names, or None on timeout / cancellation.

        Logic flow mirrors Eka main.py acquire_duts():
          1. Topology-exclusive check (new in SRPTO)
          2. PTF lock (new in SRPTO)
          3. Shared-resource conflict check (new in SRPTO)
          4. DUT-level pool allocation  ← same as Eka
             a. If topology connections exist → topology-aware match
             b. Otherwise → FIFO (simple slice)
        """
        deadline = time.time() + self._max_wait if self._max_wait > 0 else None
        poll = poll_interval if poll_interval is not None else self._poll_interval

        while True:
            # --- Check for user-requested stop ---------------------------------
            if stop_event and stop_event.is_set():
                logger.info("[%s] Cancelled while waiting for DUTs", script_name)
                return None

            # --- Timeout guard -------------------------------------------------
            if deadline and time.time() > deadline:
                logger.warning(
                    "[%s] Timed out waiting for %d DUT(s) after %.0fs",
                    script_name, req.dut_count, self._max_wait
                )
                return None

            with self._lock:
                allocated = self._try_allocate(req, script_name)
                if allocated is not None:
                    self._fire_status()
                    return allocated

            logger.debug(
                "[QUEUE][%s] Waiting for %d DUT(s)…  (pool free: %s)",
                script_name, req.dut_count, self._free_names()
            )
            time.sleep(poll)

    def release(self, duts: List[str], script_name: str, req: ResourceRequirement):
        """
        Return DUT slots (and PTF / topology lock) back to the pool.
        Mirrors Eka release_duts().
        """
        with self._lock:
            for d in duts:
                if d in self._slots:
                    self._slots[d].busy = False
                    self._slots[d].held_by = None

            if req.ptf_required and self._ptf_busy and self._ptf_held_by == script_name:
                self._ptf_busy = False
                self._ptf_held_by = None

            if req.topology_exclusive and self._topo_exclusive and self._topo_held_by == script_name:
                self._topo_exclusive = False
                self._topo_held_by = None

            # Release shared resources
            for res in req.shared_resources:
                if res in self._shared_resources:
                    self._shared_resources[res].discard(script_name)

            self._fire_status()
            logger.info(
                "[DUTPool] Released by %s → freed: %s | pool now free: %s",
                script_name, duts, self._free_names()
            )

    # ------------------------------------------------------------------
    # Public: status snapshot (mirrors Eka _exec_queue_state / _q_set_free)
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return a snapshot dict compatible with Eka's _exec_queue_state schema."""
        with self._lock:
            return {
                "free_duts":  self._free_names(),
                "busy_duts":  [s.name for s in self._slots.values() if s.busy],
                "ptf_busy":   self._ptf_busy,
                "topo_locked": self._topo_exclusive,
                "shared_resources": {k: list(v) for k, v in self._shared_resources.items()},
            }

    def register_status_callback(self, cb):
        """Register a callable(status_dict) to be invoked on every state change."""
        self._status_callbacks.append(cb)

    def set_scarcity_scores(
        self,
        scores: Dict[str, float],
        contributions: Optional[Dict[str, Dict[str, float]]] = None,
    ):
        """
        Feed in precomputed per-DUT scarcity scores (see
        engine._compute_dut_scarcity), so _find_duts_matching_topology (and
        the plain FIFO path — see _try_allocate) can prefer less-contested
        DUTs over whichever happens to come first in list/combinations
        order. Intended to be called once, by the scheduler, before any
        worker starts acquiring — see srpto/docs/scarcity_aware_allocation.md.

        `contributions`, keyed by the same script_name identifier passed to
        acquire(), is each script's own {dut: weight} breakdown — retired
        (subtracted back out of `scores`) the moment that script is
        allocated, so the live picture shrinks to reflect only scripts
        still actually waiting.
        """
        with self._lock:
            self._dut_scarcity = dict(scores)
            self._scarcity_contributions = {
                k: dict(v) for k, v in (contributions or {}).items()
            }

    def register_pending(self, dut_count: int):
        """
        Called by a worker thread entering the 'waiting' state.
        Records the largest pending DUT request so _try_allocate can apply
        the anti-starvation guard.
        """
        with self._pending_count_lock:
            if dut_count > self._max_pending_dut_count:
                self._max_pending_dut_count = dut_count

    def unregister_pending(self, dut_count: int):
        """
        Called when a worker acquires DUTs or is cancelled.
        Conservatively resets the max so the guard can relax.
        """
        with self._pending_count_lock:
            if dut_count >= self._max_pending_dut_count:
                self._max_pending_dut_count = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_allocate(self, req: ResourceRequirement, script_name: str) -> Optional[List[str]]:
        """
        One allocation attempt under the lock.
        Returns list of DUT names on success, None if not yet possible.
        """
        # ── 1. Topology exclusive guard ──────────────────────────────────────
        if self._topo_exclusive:
            return None   # wait for exclusive-lock holder to finish

        if req.topology_exclusive:
            # Need all DUTs free before grabbing topology lock
            if any(s.busy for s in self._slots.values()):
                return None
            if self._ptf_busy:
                return None

        # ── 2. PTF guard ─────────────────────────────────────────────────────
        if req.ptf_required and self._ptf_busy:
            return None

        # ── 3. Shared-resource conflict check ────────────────────────────────
        for res in req.shared_resources:
            holders = self._shared_resources.get(res, set())
            if holders:
                logger.debug(
                    "[CONFLICT] %s needs %s but it's held by %s",
                    script_name, res, holders
                )
                return None

        # ── 4. DUT-level pool allocation (matches Eka logic exactly) ─────────
        free = self._free_names()

        if len(free) < req.dut_count:
            return None     # not enough free DUTs yet

        # Topology-aware path (mirrors Eka _find_duts_matching_topology)
        if self._topology_connections and req.link_requirements:
            matched = self._find_duts_matching_topology(
                free, req.dut_count, req.link_requirements, script_name
            )
            if not matched:
                return None     # wait for matching combo
            selected = matched
        elif req.dut_names:
            # Explicit DUT names requested
            available_named = [d for d in req.dut_names if d in free]
            if len(available_named) < req.dut_count:
                return None
            selected = available_named[: req.dut_count]
        else:
            # Simple FIFO — but scarcity- and adjacency-aware: prefer the
            # free DUTs with the LOWEST (scarcity + live adjacency penalty)
            # score, tie-breaking on original free-list order. A plain
            # "give me N DUTs, no link constraint" request has no narrow
            # need of its own, but it should still avoid taking a DUT some
            # OTHER, stricter script in the batch can only get from a
            # narrow set of combinations (scarcity), and avoid a DUT
            # physically bordering another script's DUT that's busy right
            # now (adjacency). With no scores set and nothing else running,
            # every candidate ties at 0 and this reproduces the exact old
            # free[:dut_count] order — fully backward-compatible.
            ranked = sorted(
                range(len(free)),
                key=lambda i: (
                    self._dut_scarcity.get(free[i], 0.0)
                    + self._live_adjacency_penalty([free[i]], script_name),
                    i,
                )
            )
            selected = [free[i] for i in ranked[: req.dut_count]]

        # ── Anti-starvation guard ─────────────────────────────────────────────
        # If a LARGER request is currently pending, hold THIS (smaller)
        # request off rather than let it starve the larger one.
        with self._pending_count_lock:
            max_pending = self._max_pending_dut_count
        if req.topology_exclusive:
            # A topology-exclusive lock blocks EVERY other request for its
            # entire runtime, no matter how many DUTs are numerically "left
            # over" — so the remaining-DUT arithmetic below doesn't apply
            # here. Without this branch, a small exclusive test (e.g. a
            # 1-DUT reboot) can grab the lock ahead of an already-waiting,
            # larger, non-exclusive request (e.g. a 4-DUT BGP test) purely by
            # winning the polling race, then freeze that request for its
            # whole run even though enough DUTs were free the entire time.
            if max_pending > req.dut_count and len(free) >= max_pending:
                logger.debug(
                    "[%s] Anti-starvation hold: exclusive request would block "
                    "an already-pending %d-DUT request that could run now "
                    "(free=%d)",
                    script_name, max_pending, len(free)
                )
                return None
        elif max_pending > req.dut_count:
            # How many DUTs would remain free after this allocation?
            remaining = len(free) - req.dut_count
            if remaining < max_pending:
                logger.debug(
                    "[%s] Anti-starvation hold: a %d-DUT request is pending "
                    "(free=%d, would leave=%d < %d needed)",
                    script_name, max_pending, len(free), remaining, max_pending
                )
                return None

        # ── Commit allocation ─────────────────────────────────────────────────
        for d in selected:
            self._slots[d].busy = True
            self._slots[d].held_by = script_name

        if req.ptf_required:
            self._ptf_busy = True
            self._ptf_held_by = script_name

        if req.topology_exclusive:
            self._topo_exclusive = True
            self._topo_held_by = script_name

        for res in req.shared_resources:
            self._shared_resources.setdefault(res, set()).add(script_name)

        # Retire this script's scarcity contribution now that its demand is
        # settled: it has committed to `selected` and will never reconsider,
        # so its weight should stop biasing combo/FIFO choices for scripts
        # still waiting. Subtracting (not just dropping) handles the case
        # where another still-pending script shares a DUT in its own
        # contribution breakdown — only THIS script's share comes off.
        contrib = self._scarcity_contributions.pop(script_name, None)
        if contrib:
            for dut, weight in contrib.items():
                if dut in self._dut_scarcity:
                    self._dut_scarcity[dut] = max(0.0, self._dut_scarcity[dut] - weight)

        logger.info(
            "[DUTPool] Allocated to %s → DUTs: %s | PTF: %s | Exclusive: %s",
            script_name, selected, req.ptf_required, req.topology_exclusive
        )
        return selected

    def _free_names(self) -> List[str]:
        return [s.name for s in self._slots.values() if not s.busy]

    def _live_adjacency_penalty(self, candidate_duts, script_name: str) -> int:
        """
        Count how many physical links `candidate_duts` have into DUTs
        CURRENTLY held by a DIFFERENT script. Unlike scarcity (computed once
        from the whole batch), this reflects who is actually running right
        now, so it's recomputed fresh on every allocation attempt — always
        called from inside _try_allocate, which already holds self._lock,
        so reading self._slots here is safe without extra locking.

        A DUT touching two currently-busy foreign neighbors scores worse
        than one touching only one — more concurrent neighboring activity
        is more potential interference, not just a yes/no risk.
        """
        penalty = 0
        for d in candidate_duts:
            for neighbor in self._adjacency.get(d, ()):
                slot = self._slots.get(neighbor)
                if slot and slot.busy and slot.held_by != script_name:
                    penalty += 1
        return penalty

    def _find_duts_matching_topology(
        self,
        free_duts: List[str],
        needed: int,
        link_requirements: Dict[Tuple[str, str], int],
        script_name: str = "",
    ) -> Optional[List[str]]:
        """
        Topology-aware DUT matching.

        Originally a direct port of Eka's _find_duts_matching_topology
        (main.py ~3142-3206), which returned the FIRST combo (in
        itertools.combinations() order) whose inter-device link counts
        satisfy `link_requirements`. Now scarcity- AND adjacency-aware: it
        still only considers combos that satisfy the requirement, but among
        those it prefers the combo with the lowest combined score of:

          * self._dut_scarcity — avoids handing out DUTs some OTHER script
            in this run may need and has fewer alternatives for;
          * _live_adjacency_penalty — avoids handing out a DUT physically
            linked to another script's DUT that's busy RIGHT NOW, reducing
            (not eliminating) the risk of config-push bleed-over across a
            shared cable into a concurrently-running "isolated" test.

        Both are pure tiebreakers among already-valid combos — neither can
        turn a valid combo invalid, so this never blocks an allocation that
        would otherwise succeed, only chooses a better one when options tie.

        With no scores set and nothing else running (both the common case
        at a quiet pool), every candidate scores 0 and ties are broken by
        original combinations() order — identical to the old first-match
        behaviour. See srpto/docs/scarcity_aware_allocation.md and
        srpto/docs/adjacency_aware_allocation.md for the full design and
        worked examples.

        link_requirements: {(role_A, role_B): min_links}
          e.g. {("D1","D2"): 2, ("D2","D3"): 1}
        topology_connections: {(dut_A, dut_B): link_count}
          e.g. {("sonic-dut-1","sonic-dut-2"): 4}
        """
        from itertools import combinations, permutations

        if not link_requirements:
            return free_duts[:needed]

        candidates: List[Tuple[float, int, List[str]]] = []  # (combined_score, seen_order, perm)
        for combo_idx, combo in enumerate(combinations(free_duts, needed)):
            for perm in permutations(combo):
                # perm[0] → D1, perm[1] → D2, etc.
                role_map = {f"D{i+1}": name for i, name in enumerate(perm)}
                ok = True
                for (rA, rB), min_links in link_requirements.items():
                    dA = role_map.get(rA)
                    dB = role_map.get(rB)
                    if not dA or not dB:
                        ok = False
                        break
                    actual = (
                        self._topology_connections.get((dA, dB), 0)
                        or self._topology_connections.get((dB, dA), 0)
                    )
                    if actual < min_links:
                        ok = False
                        break
                if ok:
                    scarcity_score = sum(self._dut_scarcity.get(d, 0.0) for d in combo)
                    adjacency_penalty = self._live_adjacency_penalty(combo, script_name)
                    candidates.append((scarcity_score + adjacency_penalty, combo_idx, list(perm)))
                    break  # one valid permutation is enough for this combo

        if not candidates:
            return None
        candidates.sort(key=lambda c: (c[0], c[1]))
        return candidates[0][2]

    def _fire_status(self):
        snap = {
            "free_duts": self._free_names(),
            "busy_duts": [s.name for s in self._slots.values() if s.busy],
        }
        for cb in self._status_callbacks:
            try:
                cb(snap)
            except Exception:
                pass
