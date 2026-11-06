"""
srpto.scheduler.conflict
=========================
Pre-flight and runtime conflict detection.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List

from srpto.lock_manager.dut_lock import ResourceRequirement

logger = logging.getLogger("srpto.conflict")


class ConflictReport:
    def __init__(self, script_a: str, script_b: str, kind: str, detail: str):
        self.script_a = script_a
        self.script_b = script_b
        self.kind = kind
        self.detail = detail

    def __str__(self):
        return (
            f"[CONFLICT:{self.kind}] {self.script_a} <-> {self.script_b}: {self.detail}"
        )


class ConflictDetector:
    """
    Check a set of ResourceRequirement objects for scheduling conflicts.
    Returns a list of ConflictReport (warning-only; hard block is DUTPool at runtime).
    Mirrors Eka BF-12 planning-level conflict check.
    """

    def check_all(
        self, requirements: Dict[str, ResourceRequirement]
    ) -> List[ConflictReport]:
        conflicts = []
        scripts = list(requirements.items())

        for i, (path_a, req_a) in enumerate(scripts):
            for path_b, req_b in scripts[i + 1:]:
                conflicts += self._compare(path_a, req_a, path_b, req_b)

        if conflicts:
            logger.warning("[ConflictDetector] Found %d conflict(s):", len(conflicts))
            for c in conflicts:
                logger.warning("  %s", c)
        else:
            logger.info("[ConflictDetector] No pre-flight conflicts")
        return conflicts

    def _compare(
        self,
        path_a: str, req_a: ResourceRequirement,
        path_b: str, req_b: ResourceRequirement,
    ) -> List[ConflictReport]:
        a = os.path.basename(path_a)
        b = os.path.basename(path_b)
        found = []

        # Topology exclusive conflict
        if req_a.topology_exclusive or req_b.topology_exclusive:
            who = "both" if (req_a.topology_exclusive and req_b.topology_exclusive) else "one"
            found.append(ConflictReport(
                a, b, "exclusive",
                f"{who} request(s) topology exclusive lock (reboot/config-reload). "
                f"These will be serialized at runtime."
            ))

        # PTF exclusivity
        if req_a.ptf_required and req_b.ptf_required:
            found.append(ConflictReport(
                a, b, "ptf",
                "Both scripts need exclusive PTF host — will be serialized."
            ))

        # Shared resource overlap
        shared = req_a.shared_resources & req_b.shared_resources
        for res in shared:
            found.append(ConflictReport(
                a, b, "shared_resource",
                f"Both modify '{res}' — possible corruption if run in parallel."
            ))

        # Explicit DUT name overlap
        overlap_duts = set(req_a.dut_names) & set(req_b.dut_names)
        if overlap_duts:
            found.append(ConflictReport(
                a, b, "dut_overlap",
                f"Both explicitly request DUT(s): {overlap_duts}."
            ))

        return found
