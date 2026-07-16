#!/usr/bin/env python3
"""Common2 migration dashboard generator.

This script scans ``tests/common`` and produces a contributor-facing "migration
dashboard" that answers three questions for every candidate module (and, at a
finer granularity, every public function/class):

1. *What* can be migrated to ``tests/common2`` and *where* should it go
   (domain-based target directory derived from ``DIRECTORY_STRUCTURE.md``)?
2. *What is the blast radius* -- which test files import/use the code, so a
   contributor knows exactly which tests they must re-validate after migrating.
3. *How much work is it* -- a complexity/volume score bucketed into tiers and a
   global rank ``1..N`` (easiest first) so a contributor can pick something
   manageable, even a single function.

For now the dashboard is printed to the task output log. A machine-readable JSON
artifact is also emitted (``--json-out``) so a later pipeline step can push the
same data to a GitHub Project without re-computing anything.

The script has no third-party dependencies -- it only uses the standard library
so it runs on a bare pipeline agent.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import warnings
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

# tests/common contains many regex strings with invalid escape sequences that
# emit SyntaxWarning at parse time. They are irrelevant to this analysis.
warnings.filterwarnings("ignore", category=SyntaxWarning)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Files that are never migration candidates on their own.
EXCLUDED_BASENAMES = {"__init__.py", "conftest.py", "setup.py"}

# Directory names inside tests/common that hold tests/fixtures rather than
# reusable library code worth migrating as a standalone task.
EXCLUDED_DIR_PARTS = {"unit_tests", "__pycache__", ".pytest_cache"}

# Domain mapping derived from tests/common2/DIRECTORY_STRUCTURE.md. The first
# matching keyword (searched in the source path, case-insensitive) wins.
# Order matters: more specific keywords first.
DOMAIN_KEYWORDS: List[Tuple[str, str]] = [
    ("dualtor", "network/dualtor"),
    ("macsec", "security/macsec"),
    ("acl", "security/acl"),
    ("tacacs", "security/auth"),
    ("cert", "security/auth"),
    ("telemetry", "monitoring/telemetry"),
    ("sflow", "monitoring/sflow"),
    ("snappi", "monitoring/traffic_gen"),
    ("ixia", "monitoring/traffic_gen"),
    ("flow_counter", "monitoring/counters"),
    ("portstat", "monitoring/counters"),
    ("pfc", "qos/pfc"),
    ("qos", "qos"),
    ("bgp", "routing/bgp"),
    ("route", "routing"),
    ("vxlan", "routing/vxlan"),
    ("gcu", "system/config"),
    ("gu_utils", "system/config"),
    ("config_reload", "system/config"),
    ("checkpoint", "system/config"),
    ("reboot", "system/reboot"),
    ("system_health", "system/health"),
    ("system_utils", "system"),
    ("platform", "platform"),
    ("broadcom", "platform/vendor"),
    ("cisco", "platform/vendor"),
    ("mellanox", "platform/vendor"),
    ("marvell", "platform/vendor"),
    ("nokia", "platform/vendor"),
    ("barefoot", "platform/vendor"),
    ("vs_data", "platform/vendor"),
    ("sai", "platform/sai"),
    ("dhcp", "network/dhcp"),
    ("arp", "network/arp"),
    ("port_toggle", "network/interface"),
    ("multi_servers", "network"),
    ("storage_backend", "system/storage"),
    ("db_comparison", "utilities/validation"),
    ("str_utils", "utilities/helpers"),
    ("utilities", "utilities/helpers"),
    ("templates", "utilities/templates"),
    ("connections", "utilities/connection"),
    ("devices", "utilities/connection"),
    ("helpers", "utilities/helpers"),
    ("plugins", "utilities/plugins"),
    ("fixtures", "utilities/fixtures"),
]

DEFAULT_DOMAIN = "utilities/helpers"

# Authoritative registry of code already migrated to common2, keyed by the
# common2 target file. ``symbols`` are the public names that were consolidated
# there. Symbols listed here are reported as DONE (and excluded from the
# "available" work queue) so contributors don't re-migrate them.
#
# This is intentionally explicit and easy to extend as more libraries land in
# common2. Keep source paths relative to the repo root.
MIGRATED_REGISTRY: Dict[str, Dict[str, object]] = {
    "routing/bgp/bgp_route_control.py": {
        "sources": ["tests/common/helpers/bgp.py"],
        "symbols": [
            "announce_route",
            "withdraw_route",
            "announce_route_with_community",
            "withdraw_route_with_community",
            "install_route_from_exabgp",
            "update_routes",
            "BGPRouteController",
        ],
    },
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Symbol:
    """A public top-level function or class within a candidate module."""

    name: str
    kind: str  # "function" or "class"
    lineno: int
    loc: int
    has_docstring: bool
    typed_ratio: float  # 0..1 fraction of annotated params + return
    migrated: bool
    impacted_tests: List[str] = field(default_factory=list)
    score: float = 0.0
    tier: int = 0


@dataclass
class ModuleTask:
    """A migration task for one source module in tests/common."""

    rel_path: str  # e.g. tests/common/helpers/bgp.py
    dotted: str  # e.g. tests.common.helpers.bgp
    domain: str  # proposed common2 domain directory
    target_path: str  # proposed common2 file path
    loc: int
    num_functions: int
    num_classes: int
    typed_ratio: float
    documented_ratio: float
    internal_common_deps: List[str]
    has_common2_unit_tests: bool
    fully_migrated: bool
    symbols: List[Symbol] = field(default_factory=list)
    impacted_tests: List[str] = field(default_factory=list)
    impacted_consumers: List[str] = field(default_factory=list)
    score: float = 0.0
    tier: int = 0
    rank: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def iter_python_files(root: str) -> List[str]:
    """Return absolute paths of all ``*.py`` files under ``root``."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_PARTS]
        for name in filenames:
            if name.endswith(".py"):
                out.append(os.path.join(dirpath, name))
    return out


def to_dotted(rel_path: str) -> str:
    """Convert a repo-relative ``.py`` path to a dotted module path."""
    no_ext = rel_path[:-3] if rel_path.endswith(".py") else rel_path
    return no_ext.replace(os.sep, ".").replace("/", ".")


def is_test_file(rel_path: str) -> bool:
    """Heuristic: does this path look like a pytest test module?"""
    base = os.path.basename(rel_path)
    return base.startswith("test_") or base.endswith("_test.py")


def safe_parse(path: str) -> Optional[ast.Module]:
    """Parse a Python file into an AST, returning ``None`` on failure."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return ast.parse(handle.read(), filename=path)
    except (SyntaxError, ValueError):
        return None


def typed_ratio_for_function(node: ast.FunctionDef) -> float:
    """Fraction of a function's params + return that carry type annotations."""
    args = node.args
    params = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    # Ignore ``self``/``cls`` which are conventionally unannotated.
    params = [p for p in params if p.arg not in ("self", "cls")]
    slots = len(params) + 1  # +1 for the return annotation
    annotated = sum(1 for p in params if p.annotation is not None)
    if node.returns is not None:
        annotated += 1
    return annotated / slots if slots else 1.0


def resolve_domain(rel_path: str) -> str:
    """Map a source path to a proposed common2 domain directory."""
    lowered = rel_path.lower()
    for keyword, domain in DOMAIN_KEYWORDS:
        if keyword in lowered:
            return domain
    return DEFAULT_DOMAIN


# ---------------------------------------------------------------------------
# Import index (impact analysis)
# ---------------------------------------------------------------------------


def module_from_relative_import(node: ast.ImportFrom, file_rel_path: str) -> Optional[str]:
    """Resolve a relative ``from . import x`` to an absolute dotted module."""
    if node.level == 0:
        return node.module
    pkg_parts = to_dotted(os.path.dirname(file_rel_path)).split(".")
    if node.level > len(pkg_parts):
        return node.module
    base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
    if node.module:
        base = base + node.module.split(".")
    return ".".join(base) if base else node.module


@dataclass
class ConsumerImports:
    """The set of common modules a single consumer file imports."""

    modules: Set[str] = field(default_factory=set)  # dotted module targets
    names: Set[str] = field(default_factory=set)  # imported symbol names


def build_import_index(
    tests_root_abs: str, repo_root: str
) -> Dict[str, ConsumerImports]:
    """Map each consumer file (repo-relative) to the common modules it imports.

    We only track imports that resolve into ``tests.common`` since those are the
    migration candidates whose blast radius we care about.
    """
    index: Dict[str, ConsumerImports] = {}
    for abs_path in iter_python_files(tests_root_abs):
        rel = os.path.relpath(abs_path, repo_root).replace(os.sep, "/")
        tree = safe_parse(abs_path)
        if tree is None:
            continue
        consumer = ConsumerImports()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("tests.common"):
                        consumer.modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                resolved = module_from_relative_import(node, rel)
                if not resolved:
                    continue
                if resolved.startswith("common.") or resolved == "common":
                    resolved = "tests." + resolved
                if not resolved.startswith("tests.common"):
                    continue
                for alias in node.names:
                    consumer.names.add(alias.name)
                    # ``from tests.common.x import y`` -> y may itself be a module.
                    consumer.modules.add(resolved + "." + alias.name)
                consumer.modules.add(resolved)
        if consumer.modules:
            index[rel] = consumer
    return index


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def bucket_tier(score: float, thresholds: List[float]) -> int:
    """Return a 1-based tier for ``score`` given ascending ``thresholds``."""
    for i, threshold in enumerate(thresholds, start=1):
        if score <= threshold:
            return i
    return len(thresholds) + 1


def compute_module_score(task: ModuleTask) -> float:
    """Weighted effort score. Higher == more work / higher risk.

    Combines volume (LOC, symbol count), blast radius (impacted tests),
    coupling (internal common deps), and remaining quality gap (missing type
    hints, docs, unit tests) required to satisfy common2 standards.
    """
    volume = task.loc / 40.0 + (task.num_functions + task.num_classes) * 1.5
    blast = len(task.impacted_tests) * 1.2
    coupling = len(task.internal_common_deps) * 2.0
    quality_gap = (1.0 - task.typed_ratio) * 6.0 + (1.0 - task.documented_ratio) * 3.0
    unit_gap = 0.0 if task.has_common2_unit_tests else 4.0
    return round(volume + blast + coupling + quality_gap + unit_gap, 2)


def compute_symbol_score(symbol: Symbol) -> float:
    """Per-function/class effort score for granular tasks."""
    volume = symbol.loc / 25.0 + 1.0
    blast = len(symbol.impacted_tests) * 1.2
    quality_gap = (1.0 - symbol.typed_ratio) * 3.0 + (0.0 if symbol.has_docstring else 1.5)
    return round(volume + blast + quality_gap, 2)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def collect_common2_symbols(common2_abs: str) -> Set[str]:
    """Public symbol names already defined anywhere in common2."""
    names: Set[str] = set()
    if not os.path.isdir(common2_abs):
        return names
    for abs_path in iter_python_files(common2_abs):
        if os.sep + "unit_tests" + os.sep in abs_path:
            continue
        tree = safe_parse(abs_path)
        if tree is None:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("_"):
                    names.add(node.name)
    return names


def registry_migrated_symbols_for(rel_path: str) -> Set[str]:
    """Symbols the migration registry marks as already migrated from a source."""
    migrated: Set[str] = set()
    normalized = rel_path.replace(os.sep, "/")
    for entry in MIGRATED_REGISTRY.values():
        sources = [s.replace(os.sep, "/") for s in entry.get("sources", [])]  # type: ignore[arg-type]
        if normalized in sources:
            migrated.update(entry.get("symbols", []))  # type: ignore[arg-type]
    return migrated


def analyze_module(
    abs_path: str,
    repo_root: str,
    import_index: Dict[str, ConsumerImports],
    common2_unit_test_modules: Set[str],
    registry_symbols_lookup,
) -> Optional[ModuleTask]:
    """Build a :class:`ModuleTask` for one candidate source module."""
    rel = os.path.relpath(abs_path, repo_root).replace(os.sep, "/")
    tree = safe_parse(abs_path)
    if tree is None:
        return None

    with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
        source_lines = handle.read().splitlines()
    loc = sum(1 for ln in source_lines if ln.strip() and not ln.strip().startswith("#"))

    dotted = to_dotted(rel)
    domain = resolve_domain(rel)
    target_path = "tests/common2/" + domain + "/" + os.path.basename(rel)

    registry_migrated = registry_symbols_lookup(rel)

    symbols: List[Symbol] = []
    typed_values: List[float] = []
    documented = 0
    total_symbols = 0
    internal_deps: Set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and "common" in node.module:
            internal_deps.add(node.module)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "tests.common" in alias.name:
                    internal_deps.add(alias.name)

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_"):
                continue
            total_symbols += 1
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            sym_loc = max(1, end - node.lineno + 1)
            has_doc = ast.get_docstring(node) is not None
            if has_doc:
                documented += 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tr = typed_ratio_for_function(node)
                kind = "function"
            else:
                # Class type-hint quality = average of its public methods.
                method_ratios = [
                    typed_ratio_for_function(m)
                    for m in node.body
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not m.name.startswith("_")
                ]
                tr = sum(method_ratios) / len(method_ratios) if method_ratios else 0.0
                kind = "class"
            typed_values.append(tr)
            symbols.append(
                Symbol(
                    name=node.name,
                    kind=kind,
                    lineno=node.lineno,
                    loc=sym_loc,
                    has_docstring=has_doc,
                    typed_ratio=round(tr, 2),
                    migrated=node.name in registry_migrated,
                )
            )

    if not symbols:
        return None

    typed_ratio = round(sum(typed_values) / len(typed_values), 2) if typed_values else 0.0
    documented_ratio = round(documented / total_symbols, 2) if total_symbols else 0.0

    # Impact analysis: which consumers import this module (or a symbol from it)?
    impacted_consumers: List[str] = []
    impacted_tests: List[str] = []
    for consumer_rel, imports in import_index.items():
        if consumer_rel == rel:
            continue
        hit = dotted in imports.modules or any(
            m == dotted or m.startswith(dotted + ".") for m in imports.modules
        )
        if not hit:
            continue
        impacted_consumers.append(consumer_rel)
        if is_test_file(consumer_rel):
            impacted_tests.append(consumer_rel)

    impacted_consumers.sort()
    impacted_tests.sort()

    # Attribute impacted tests to individual symbols by name usage.
    consumer_text_cache: Dict[str, str] = {}
    for sym in symbols:
        if sym.migrated:
            continue
        sym_tests: List[str] = []
        for consumer_rel in impacted_tests:
            text = consumer_text_cache.get(consumer_rel)
            if text is None:
                consumer_abs = os.path.join(repo_root, consumer_rel)
                try:
                    with open(consumer_abs, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    text = ""
                consumer_text_cache[consumer_rel] = text
            if sym.name in text:
                sym_tests.append(consumer_rel)
        sym.impacted_tests = sym_tests

    fully_migrated = all(s.migrated for s in symbols)

    task = ModuleTask(
        rel_path=rel,
        dotted=dotted,
        domain=domain,
        target_path=target_path,
        loc=loc,
        num_functions=sum(1 for s in symbols if s.kind == "function"),
        num_classes=sum(1 for s in symbols if s.kind == "class"),
        typed_ratio=typed_ratio,
        documented_ratio=documented_ratio,
        internal_common_deps=sorted(internal_deps),
        has_common2_unit_tests=dotted in common2_unit_test_modules,
        fully_migrated=fully_migrated,
        symbols=symbols,
        impacted_tests=impacted_tests,
        impacted_consumers=impacted_consumers,
    )
    return task


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def rank_and_score(tasks: List[ModuleTask], max_tier: int) -> None:
    """Compute scores, tiers, and global rank (easiest first) in place."""
    for task in tasks:
        task.score = compute_module_score(task)
        for sym in task.symbols:
            sym.score = compute_symbol_score(sym)

    if not tasks:
        return

    scores = sorted(t.score for t in tasks)
    # Even quantile thresholds for tiering.
    step = len(scores) / max_tier if max_tier else len(scores)
    thresholds = [scores[min(len(scores) - 1, int(step * i) - 1)] for i in range(1, max_tier)]

    for task in tasks:
        task.tier = bucket_tier(task.score, thresholds)
        for sym in task.symbols:
            sym.tier = bucket_tier(sym.score, thresholds)

    for rank, task in enumerate(sorted(tasks, key=lambda t: (t.score, t.rel_path)), start=1):
        task.rank = rank


def _bar(pct: float, width: int = 10) -> str:
    filled = int(round(pct * width))
    return "#" * filled + "-" * (width - filled)


def print_dashboard(
    tasks: List[ModuleTask],
    done_tasks: List[ModuleTask],
    max_tier: int,
    top: Optional[int],
) -> None:
    """Print the human-readable migration dashboard to stdout."""
    ordered = sorted(tasks, key=lambda t: t.rank)
    total_tests = len({t for task in tasks for t in task.impacted_tests})

    print("=" * 100)
    print(" SONiC tests/common -> tests/common2 MIGRATION DASHBOARD")
    print("=" * 100)
    print()
    print("Summary")
    print("-" * 100)
    print(f"  Candidate modules available for migration : {len(tasks)}")
    print(f"  Modules already fully migrated            : {len(done_tasks)}")
    print(f"  Distinct test files impacted (all tasks)  : {total_tests}")
    print(f"  Granular sub-tasks (public funcs/classes) : "
          f"{sum(len([s for s in t.symbols if not s.migrated]) for t in tasks)}")
    print(f"  Complexity tiers                          : 1 (easiest) .. {max_tier + 1} (hardest)")
    print()
    print("  How to use this dashboard:")
    print("    * Pick a LOW rank / LOW tier task to start small -- even a single function counts.")
    print("    * 'Impacted tests' are the tests you must re-run/validate after migrating.")
    print("    * 'Target' is the proposed tests/common2 domain path (see DIRECTORY_STRUCTURE.md).")
    print("    * Every migrated function needs type hints, a docstring, and unit tests (>=80% cov).")
    print()

    header = (
        f"{'Rank':>4}  {'Tier':>4}  {'Score':>6}  {'Tests':>5}  {'LOC':>5}  "
        f"{'Fns':>3}  {'Typed':>6}  {'UT':>3}  {'Module':<44}  {'Target domain'}"
    )
    print("Migration work queue (easiest first)")
    print("-" * 100)
    print(header)
    print("-" * 100)
    shown = ordered if top is None else ordered[:top]
    for task in shown:
        module_disp = task.rel_path.replace("tests/common/", "")
        if len(module_disp) > 44:
            module_disp = "..." + module_disp[-41:]
        print(
            f"{task.rank:>4}  {task.tier:>4}  {task.score:>6}  "
            f"{len(task.impacted_tests):>5}  {task.loc:>5}  "
            f"{task.num_functions + task.num_classes:>3}  "
            f"{int(task.typed_ratio * 100):>5}%  "
            f"{'Y' if task.has_common2_unit_tests else 'N':>3}  "
            f"{module_disp:<44}  {task.domain}"
        )
    if top is not None and len(ordered) > top:
        print(f"  ... and {len(ordered) - top} more (increase --top or read the JSON artifact).")
    print()

    # Granular detail for the most approachable tasks.
    detail_count = min(len(shown), 15 if top is None else top)
    print("Granular sub-tasks for the top approachable modules")
    print("-" * 100)
    for task in shown[:detail_count]:
        print()
        print(f"[Rank {task.rank} | Tier {task.tier} | Score {task.score}] {task.rel_path}")
        print(f"    Proposed target : {task.target_path}")
        print(f"    Type-hint cover : {_bar(task.typed_ratio)} {int(task.typed_ratio * 100)}%   "
              f"Docstrings: {int(task.documented_ratio * 100)}%   "
              f"Unit tests in common2: {'yes' if task.has_common2_unit_tests else 'no'}")
        if task.internal_common_deps:
            deps = ", ".join(task.internal_common_deps[:4])
            more = "" if len(task.internal_common_deps) <= 4 else f" (+{len(task.internal_common_deps) - 4} more)"
            print(f"    Depends on      : {deps}{more}")
        pending = [s for s in task.symbols if not s.migrated]
        migrated = [s for s in task.symbols if s.migrated]
        if migrated:
            print(f"    Already migrated: {', '.join(s.name for s in migrated)}")
        print(f"    Function-level tasks ({len(pending)}):")
        for sym in sorted(pending, key=lambda s: s.score):
            tests_preview = ", ".join(os.path.basename(t) for t in sym.impacted_tests[:3])
            if len(sym.impacted_tests) > 3:
                tests_preview += f", +{len(sym.impacted_tests) - 3} more"
            tests_preview = tests_preview or "no direct test references found"
            print(
                f"        - [T{sym.tier} score {sym.score:>5}] {sym.kind} {sym.name}() "
                f"| {sym.loc} LOC | typed {int(sym.typed_ratio * 100)}% "
                f"| {len(sym.impacted_tests)} tests: {tests_preview}"
            )
        # Impacted test list (bounded).
        if task.impacted_tests:
            preview = task.impacted_tests[:8]
            print(f"    Impacted tests ({len(task.impacted_tests)}): "
                  + ", ".join(p.replace('tests/', '') for p in preview)
                  + (f" ... (+{len(task.impacted_tests) - 8})" if len(task.impacted_tests) > 8 else ""))
    print()

    if done_tasks:
        print("Already migrated (for reference)")
        print("-" * 100)
        for task in done_tasks:
            print(f"    {task.rel_path}  ->  {task.target_path}  "
                  f"({', '.join(s.name for s in task.symbols if s.migrated)})")
        print()

    print("=" * 100)
    print("End of dashboard. Machine-readable data is in the JSON artifact (see --json-out).")
    print("=" * 100)


def build_json(tasks: List[ModuleTask], done_tasks: List[ModuleTask], max_tier: int) -> dict:
    """Assemble the structured payload for later GitHub Project upload."""
    return {
        "schema_version": 1,
        "summary": {
            "available_modules": len(tasks),
            "migrated_modules": len(done_tasks),
            "distinct_impacted_tests": len({t for task in tasks for t in task.impacted_tests}),
            "granular_subtasks": sum(
                len([s for s in t.symbols if not s.migrated]) for t in tasks
            ),
            "max_tier": max_tier + 1,
        },
        "tasks": [asdict(t) for t in sorted(tasks, key=lambda x: x.rank)],
        "migrated": [asdict(t) for t in done_tasks],
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def default_repo_root() -> str:
    """Repo root = three levels up from this script (.azure-pipelines/common2/scripts)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, os.pardir, os.pardir, os.pardir))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=default_repo_root(),
                        help="Path to the sonic-mgmt repository root.")
    parser.add_argument("--common-dir", default="tests/common",
                        help="Source directory to scan for migration candidates.")
    parser.add_argument("--common2-dir", default="tests/common2",
                        help="Destination common2 directory (for migrated detection).")
    parser.add_argument("--tests-dir", default="tests",
                        help="Test tree scanned to compute migration impact.")
    parser.add_argument("--max-tier", type=int, default=5,
                        help="Number of complexity tiers (produces tiers 1..max-tier+1).")
    parser.add_argument("--top", type=int, default=40,
                        help="Show only the N easiest tasks in the log (0 = all).")
    parser.add_argument("--json-out", default="",
                        help="Optional path to write the machine-readable JSON artifact.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    repo_root = os.path.abspath(args.repo_root)
    common_abs = os.path.join(repo_root, args.common_dir)
    common2_abs = os.path.join(repo_root, args.common2_dir)
    tests_abs = os.path.join(repo_root, args.tests_dir)

    if not os.path.isdir(common_abs):
        print(f"ERROR: common dir not found: {common_abs}", file=sys.stderr)
        return 2

    print(f"Scanning source modules under: {args.common_dir}")
    print(f"Computing impact against test tree: {args.tests_dir}")
    print(f"Detecting migrated code in: {args.common2_dir}")
    print()

    # 1. Which common2 modules have unit tests (module dotted path form).
    common2_unit_test_modules: Set[str] = set()
    unit_tests_dir = os.path.join(common2_abs, "unit_tests")
    if os.path.isdir(unit_tests_dir):
        for abs_path in iter_python_files(unit_tests_dir):
            rel = os.path.relpath(abs_path, common2_abs).replace(os.sep, "/")
            # unit_tests/routing/bgp/unit_test_bgp_route_helper.py -> routing.bgp mirror
            mirror = rel.replace("unit_tests/", "").rsplit("/", 1)[0]
            common2_unit_test_modules.add("tests.common2." + mirror.replace("/", "."))

    _ = collect_common2_symbols(common2_abs)  # reserved for future soft-match hints

    # 2. Reverse import index for impact analysis.
    import_index = build_import_index(tests_abs, repo_root)

    # 3. Analyze every candidate module.
    tasks: List[ModuleTask] = []
    done_tasks: List[ModuleTask] = []
    for abs_path in iter_python_files(common_abs):
        base = os.path.basename(abs_path)
        if base in EXCLUDED_BASENAMES or is_test_file(base):
            continue
        task = analyze_module(
            abs_path,
            repo_root,
            import_index,
            common2_unit_test_modules,
            registry_migrated_symbols_for,
        )
        if task is None:
            continue
        if task.fully_migrated:
            done_tasks.append(task)
        else:
            tasks.append(task)

    rank_and_score(tasks, args.max_tier)

    top = None if args.top in (0, None) else args.top
    print_dashboard(tasks, done_tasks, args.max_tier, top)

    if args.json_out:
        out_path = args.json_out
        if not os.path.isabs(out_path):
            out_path = os.path.join(repo_root, out_path)
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(build_json(tasks, done_tasks, args.max_tier), handle, indent=2)
        print(f"\nWrote machine-readable dashboard JSON to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
