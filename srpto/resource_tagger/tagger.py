"""
srpto.resource_tagger.tagger
==============================
Reads resource declarations from two sources:

1. **YAML resource-map file** (explicit, recommended for community framework):

   # resources.yaml
   test_bgp_gr.py:
     dut_count: 2
     dut_names: []          # empty = any 2 DUTs
     ptf_required: false
     topology_exclusive: false
     shared_resources: []
     min_topology:
       - "D1D2:2"           # needs >=2 links between D1 and D2

   test_acl.py:
     dut_count: 1
     shared_resources:
       - "vlan:100"
       - "portchannel:Po1"

   test_snmp.py:
     dut_count: 1

   test_warm_reboot.py:
     dut_count: 1
     topology_exclusive: true    # takes whole topology lock

2. **Inline pytest markers** (zero-config for scripts that already use pytest):

   @pytest.mark.srpto_resources(dut_count=2, min_topology=["D1D2:2"])
   def test_bgp_gr(duthosts, tbinfo):
       ...

3. **Auto-detection from spytest @pytest.mark.topology() and vars files**
   (same logic as Eka _parse_spytest_script, lines 6832-6865).

Priority: explicit YAML > inline marker > auto-detect.
"""

from __future__ import annotations

import ast
import re
import os
import logging
import yaml
from typing import Dict, List, Optional, Tuple

from srpto.lock_manager.dut_lock import ResourceRequirement

logger = logging.getLogger("srpto.resource_tagger")


# ---------------------------------------------------------------------------
# Link requirement parser (mirrors Eka _parse_link_requirements)
# ---------------------------------------------------------------------------

def parse_link_requirements(min_topology: List[str]) -> Dict[Tuple[str, str], int]:
    """
    Convert min_topology strings like ["D1D2:2", "D2D3:1"] into
    {("D1","D2"): 2, ("D2","D3"): 1}.

    Direct port of Eka's _parse_link_requirements (main.py), extended with:

    * Pair-order canonicalization — "D1D2:2" and "D2D1:2" describe the same
      physical pair, just spelled in the order a given test case happened to
      write it. Without canonicalizing, they'd land on two different dict
      keys — ("D1","D2") vs ("D2","D1") — which happens to still work at
      match time (the DUTPool lookup already checks both directions) but
      silently hides the duplication instead of merging it.
    * Max-merge on collision — when a script has several test cases with
      differing requirements for the SAME pair (e.g. tc1 needs "D1D2:1", tc2
      needs "D1D2:3"), min_topology now contains both entries (see
      _parse_spytest_topology). The single ResourceRequirement handed to the
      scheduler must cover the toughest test case, so take the max per pair
      rather than letting whichever entry appears last silently win.

    Note: DUT-TGEN entries (e.g. "D1T1:2") do NOT match this pattern (there's
    no second literal "D") and are intentionally skipped here — they're a
    different resource (a traffic generator, not a DUT) and are parsed
    separately by parse_tgen_link_requirements().
    """
    result: Dict[Tuple[str, str], int] = {}
    for entry in (min_topology or []):
        # Match DxDy:N or DxDy (N defaults to 1)
        m = re.match(r'D(\d+)D(\d+)(?::(\d+))?$', entry, re.IGNORECASE)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            lo, hi = (a, b) if a <= b else (b, a)
            key = (f"D{lo}", f"D{hi}")
            links = int(m.group(3)) if m.group(3) else 1
            result[key] = max(result.get(key, 0), links)
    return result


def parse_tgen_link_requirements(min_topology: List[str]) -> Dict[str, int]:
    """
    Convert min_topology strings like ["D1T1:2", "D2T1:2"] into
    {"D1": 2, "D2": 2} — the minimum traffic-generator (TGEN/T1) link count
    required on each DUT role.

    Previously these entries were silently dropped by parse_link_requirements
    (a "DxTy" token has no second literal "D", so it never matched that
    regex), which meant a script's TGEN requirement never reached the
    scheduler at all.
    """
    result: Dict[str, int] = {}
    for entry in (min_topology or []):
        m = re.match(r'D(\d+)T(\d+)(?::(\d+))?$', entry, re.IGNORECASE)
        if m:
            dA = f"D{m.group(1)}"
            links = int(m.group(3)) if m.group(3) else 1
            result[dA] = max(result.get(dA, 0), links)
    return result


# ---------------------------------------------------------------------------
# spytest @pytest.mark.topology auto-detect
# ---------------------------------------------------------------------------

def _tgen_links_from_port_names(
    port_names: List[str],
) -> Optional[Tuple[int, List[str]]]:
    """
    Given a list of port name strings like ["T1D1P1", "T1D2P1", "T1D2P2"],
    compute (dut_count, min_topology).

    Returns None if no valid TxDyPz tokens are found.
    This is a shared helper used by patterns 4, 5, 6, and 7.
    """
    dut_indices = re.findall(r'T\d+D(\d+)P\d+', " ".join(port_names), re.IGNORECASE)
    if not dut_indices:
        return None
    dut_count = max(int(d) for d in dut_indices)
    tgen_links: Dict[int, int] = {}
    for pn in port_names:
        m = re.search(r'T\d+D(\d+)P\d+', pn, re.IGNORECASE)
        if m:
            di = int(m.group(1))
            tgen_links[di] = tgen_links.get(di, 0) + 1
    min_topology = [f"D{di}T1:{cnt}" for di, cnt in sorted(tgen_links.items())]
    return dut_count, min_topology


def _parse_spytest_topology(source: str) -> Tuple[int, List[str]]:
    """
    Extract dut_count and min_topology from spytest source code.

    Detection priority (highest wins):
      1.  st.ensure_min_topology("D1T1:2", "D1D2:4", ...)  — explicit topology string
      2.  @pytest.mark.topology("D1D2:2", ...) markers
      3.  pytest_topo("any") / @pytest.mark.topology("any") — topology-agnostic
      4.  tgapi.get_handles_byname("T1D1P1", "T1D2P1") — DUT idx encoded in port name
      5.  tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D2P1]) — port attr in list arg
      6.  Multiple tgapi.get_handle_byname("T1D1P1") — scatter pattern (BGP/ACL tests)
      7.  tg_port_list = [vars.T1D1P1, ...] — pre-assigned list pattern
      8.  tgen_obj_dict[vars['tgen_list'][N]] — legacy dict access (→ 1 DUT + TGen)
      9.  tgapi.get_chassis(vars) — single-chassis no named ports (→ 1 DUT + TGen)
      10. duthosts heuristic fallback (community framework scripts)

    Patterns 1 and 2 scan the WHOLE file (every occurrence, not just the
    first) and merge the results. A single script/module commonly holds
    several test cases, each declaring its own topology need (e.g. tc1:
    ensure_min_topology("D1D2:1"), tc2: ensure_min_topology("D1D2:3"), tc3:
    ensure_min_topology("D1")) — but srpto allocates ONE DUT set for the
    whole file (all test cases share one subprocess run), so the requirement
    handed to the scheduler must be the union of every test case's need, not
    just whichever call happens to appear first in the source.
    """
    dut_count = 1
    min_topology: List[str] = []

    # ── 1. st.ensure_min_topology("D1T1:2", ...) ─────────────────────────────
    ensure_matches = list(re.finditer(r'ensure_min_topology\s*\(([^)]+)\)', source))
    if ensure_matches:
        collected: List[str] = []
        for ensure_match in ensure_matches:
            args_str = ensure_match.group(1)
            items = re.findall(r'["\'](\w[\w:]*)["\']', args_str)
            # Filter out non-topology keywords like CONSOLE_ONLY
            topo_items = [i for i in items if i not in ("CONSOLE_ONLY",) and re.match(r'D\d', i)]
            collected.extend(topo_items)
        if collected:
            min_topology = collected
            all_d_refs = re.findall(r'D(\d+)', " ".join(collected))
            if all_d_refs:
                dut_count = max(int(d) for d in all_d_refs)
        # "D1" alone everywhere (no DxTy/DxDy links) → 1 DUT, no TGen.
        # Return regardless — this pattern outranks 2-10.
        return dut_count, min_topology

    # ── 2. @pytest.mark.topology("D1D2:2", ...) ──────────────────────────────
    topo_marks = list(re.finditer(r'@pytest\.mark\.topology\s*\(([^)]+)\)', source))
    if topo_marks:
        _GENERIC_TOPOS = {"any", "t0", "t1", "ptf32", "t0-116", "t1-lag", "t0-56"}
        collected = []
        for topo_mark in topo_marks:
            items = re.findall(r'["\']([^"\']+)["\']', topo_mark.group(1))
            if items and not (set(items) <= _GENERIC_TOPOS):
                collected.extend(items)
        if collected:
            min_topology = collected
            all_d_refs = re.findall(r'D(\d+)', " ".join(collected))
            if all_d_refs:
                dut_count = max(int(d) for d in all_d_refs)
            return dut_count, min_topology
        # Every @pytest.mark.topology(...) in the file was topology-agnostic
        # ("any"/"t0"/...) → 1 DUT, no concrete link requirement.
        return 1, []

    # ── 3. pytest_topo("any") standalone call ────────────────────────────────
    pt_match = re.search(r'pytest_topo\s*\(\s*["\']([^"\']+)["\']\s*\)', source)
    if pt_match:
        val = pt_match.group(1)
        _GENERIC_TOPOS = {"any", "t0", "t1", "ptf32", "t0-116", "t1-lag", "t0-56"}
        if val in _GENERIC_TOPOS:
            return 1, []
        return 1, [val]

    # ── 4. tgapi.get_handles_byname("T1D1P1", "T1D2P1", ...) ────────────────
    byn = re.search(r'get_handles_byname\s*\(([^)]+)\)', source)
    if byn:
        port_names = re.findall(r'["\']([^"\']+)["\']', byn.group(1))
        result = _tgen_links_from_port_names(port_names)
        if result:
            return result

    # ── 5. tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D2P1, ...]) ──────────
    gh = re.search(r'get_handles\s*\([^)]+\[([^\]]+)\]', source)
    if gh:
        port_refs = re.findall(r'T\d+D\d+P\d+', gh.group(1), re.IGNORECASE)
        result = _tgen_links_from_port_names(port_refs)
        if result:
            return result

    # ── 6. Multiple tgapi.get_handle_byname("T1D1P1") — scatter pattern ──────
    scatter = re.findall(r'get_handle_byname\s*\(\s*["\']([^"\']+)["\']\s*\)', source)
    if scatter:
        result = _tgen_links_from_port_names(scatter)
        if result:
            return result

    # ── 7. tg_port_list = [vars.T1D1P1, vars.T1D1P2, ...] ───────────────────
    lm = re.search(r'tg_port_list\s*=\s*\[([^\]]+)\]', source)
    if lm:
        port_refs = re.findall(r'T\d+D\d+P\d+', lm.group(1), re.IGNORECASE)
        result = _tgen_links_from_port_names(port_refs)
        if result:
            return result

    # ── 8. tgen_obj_dict[vars['tgen_list'][N]] — legacy dict access ──────────
    if re.search(r'tgen_obj_dict\s*\[', source):
        return 1, ["D1T1:1"]

    # ── 9. tgapi.get_chassis(vars) — no named ports ───────────────────────────
    if re.search(r'tgapi\.get_chassis\s*\(', source):
        return 1, ["D1T1:1"]

    # ── 10. duthosts heuristic fallback (community framework) ────────────────
    if len(re.findall(r'\bduthosts?\b', source)) > 2:
        dut_count = 2

    return dut_count, min_topology


def _detect_topology_exclusive(source: str) -> bool:
    """Detect if a test triggers topology-exclusive operations."""
    patterns = [
        r'\bconfig\s+reload\b',
        r'\breboot\b',
        r'\bwarm.?reboot\b',
        r'\bfast.?reboot\b',
        r'reload_minigraph',
        r'config_reload',
        r'platform_reboot',
    ]
    for p in patterns:
        if re.search(p, source, re.IGNORECASE):
            return True
    return False


def _detect_shared_resources(source: str) -> List[str]:
    """Extract shared resource identifiers from test source (best-effort)."""
    resources = []
    # VLAN IDs
    for vlan_id in re.findall(r'\bvlan[_\s-]?(\d{2,4})\b', source, re.IGNORECASE):
        resources.append(f"vlan:{vlan_id}")
    # Port channels
    for pc in re.findall(r'\bPortChannel(\d+)\b', source, re.IGNORECASE):
        resources.append(f"portchannel:{pc}")
    # Deduplicate
    return list(dict.fromkeys(resources))


# ---------------------------------------------------------------------------
# Main tagger class
# ---------------------------------------------------------------------------

class ResourceTagger:
    """
    Resolves ResourceRequirement for every test script in a run.

    Usage:
        tagger = ResourceTagger(resource_map_path="resources.yaml")
        req = tagger.get_requirement("tests/bgp/test_bgp_gr.py")
    """

    def __init__(self, resource_map_path: Optional[str] = None):
        self._explicit_map: Dict[str, dict] = {}
        if resource_map_path and os.path.exists(resource_map_path):
            with open(resource_map_path) as f:
                self._explicit_map = yaml.safe_load(f) or {}
            logger.info(
                "[Tagger] Loaded %d explicit entries from %s",
                len(self._explicit_map), resource_map_path
            )

    def get_requirement(
        self, script_path: str, source_code: Optional[str] = None
    ) -> ResourceRequirement:
        """
        Return a ResourceRequirement for the given script.

        Resolution order:
          1. Explicit YAML entry (by basename or full path)
          2. Inline @pytest.mark.srpto_resources (from source_code AST)
          3. Auto-detect from spytest @pytest.mark.topology + heuristics
          4. Default: 1 DUT, no PTF, no exclusive
        """
        basename = os.path.basename(script_path)

        # ── 1. Explicit YAML ─────────────────────────────────────────────────
        raw = self._explicit_map.get(basename) or self._explicit_map.get(script_path)
        if raw:
            return self._from_dict(raw)

        # ── 2. Inline marker (AST) ───────────────────────────────────────────
        if source_code:
            marker_req = self._from_inline_marker(source_code)
            if marker_req:
                return marker_req

        # ── 3. Auto-detect ───────────────────────────────────────────────────
        if source_code:
            return self._auto_detect(source_code)

        # ── 4. Fallback default ──────────────────────────────────────────────
        logger.debug("[Tagger] No resource info for %s → default 1-DUT", basename)
        return ResourceRequirement()

    def build_resource_map_from_scripts(
        self, script_paths: List[str], read_fn=None
    ) -> Dict[str, ResourceRequirement]:
        """
        Analyse a list of scripts and return {path: ResourceRequirement}.
        read_fn(path) -> source_str — optional, defaults to open().
        """
        result = {}
        for path in script_paths:
            source = None
            try:
                if read_fn:
                    source = read_fn(path)
                elif os.path.exists(path):
                    with open(path) as f:
                        source = f.read()
            except Exception as e:
                logger.warning("[Tagger] Cannot read %s: %s", path, e)
            result[path] = self.get_requirement(path, source)
            logger.info(
                "[Tagger] %s → dut_count=%d | ptf=%s | exclusive=%s | links=%s | tgen_links=%s",
                os.path.basename(path),
                result[path].dut_count,
                result[path].ptf_required,
                result[path].topology_exclusive,
                result[path].link_requirements,
                result[path].tgen_link_requirements,
            )
        return result

    def generate_resource_map_yaml(
        self, script_paths: List[str], read_fn=None
    ) -> str:
        """
        Auto-generate a resources.yaml skeleton from script analysis.
        Users can edit and refine this file.
        """
        reqs = self.build_resource_map_from_scripts(script_paths, read_fn)
        out = {}
        for path, req in reqs.items():
            entry = {
                "dut_count": req.dut_count,
                "ptf_required": req.ptf_required,
                "topology_exclusive": req.topology_exclusive,
            }
            if req.dut_names:
                entry["dut_names"] = req.dut_names
            if req.shared_resources:
                entry["shared_resources"] = sorted(req.shared_resources)
            if req.link_requirements or req.tgen_link_requirements:
                # Serialize back to min_topology strings
                topo_strs = [
                    f"{rA}{rB}:{n}" for (rA, rB), n in req.link_requirements.items()
                ]
                topo_strs += [
                    f"{rA}T1:{n}" for rA, n in req.tgen_link_requirements.items()
                ]
                entry["min_topology"] = topo_strs
            out[os.path.basename(path)] = entry
        return yaml.dump(out, default_flow_style=False, sort_keys=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _from_dict(self, raw: dict) -> ResourceRequirement:
        min_topo = raw.get("min_topology", [])
        link_req = parse_link_requirements(min_topo)
        tgen_req = parse_tgen_link_requirements(min_topo)
        return ResourceRequirement(
            dut_count=raw.get("dut_count", 1),
            dut_names=raw.get("dut_names", []),
            ptf_required=raw.get("ptf_required", False),
            topology_exclusive=raw.get("topology_exclusive", False),
            shared_resources=set(raw.get("shared_resources", [])),
            link_requirements=link_req,
            tgen_link_requirements=tgen_req,
        )

    def _from_inline_marker(self, source: str) -> Optional[ResourceRequirement]:
        """Parse @pytest.mark.srpto_resources(...) from source."""
        m = re.search(
            r'@pytest\.mark\.srpto_resources\s*\(([^)]+)\)', source
        )
        if not m:
            return None
        try:
            # Evaluate keyword args safely using ast.literal_eval on each value
            args_str = m.group(1)
            raw = {}
            for kv in re.finditer(r'(\w+)\s*=\s*([^,)]+)', args_str):
                key = kv.group(1).strip()
                val_str = kv.group(2).strip()
                try:
                    raw[key] = ast.literal_eval(val_str)
                except Exception:
                    raw[key] = val_str
            return self._from_dict(raw)
        except Exception as e:
            logger.warning("[Tagger] Cannot parse inline marker: %s", e)
            return None

    def _auto_detect(self, source: str) -> ResourceRequirement:
        """Best-effort auto-detection from spytest patterns."""
        dut_count, min_topo = _parse_spytest_topology(source)
        link_req = parse_link_requirements(min_topo)
        tgen_req = parse_tgen_link_requirements(min_topo)
        topo_exclusive = _detect_topology_exclusive(source)
        shared = set(_detect_shared_resources(source))

        # PTF heuristic: any reference to ptfhost or scapy traffic
        ptf_required = bool(
            re.search(r'\bptfhost\b|\bscapy\b|\bptf_runner\b', source)
        )

        return ResourceRequirement(
            dut_count=dut_count,
            ptf_required=ptf_required,
            topology_exclusive=topo_exclusive,
            shared_resources=shared,
            link_requirements=link_req,
            tgen_link_requirements=tgen_req,
        )
