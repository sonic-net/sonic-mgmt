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

For now the dashboard is printed to the task output log. A commented, human-
readable YAML artifact is emitted (``--yaml-out``) as the primary machine record
(comments explain what rank/tier/score mean). A JSON artifact can also be emitted
(``--json-out``) for a later pipeline step that pushes the data to a GitHub
Project programmatically.

The script has no third-party dependencies -- it only uses the standard library
so it runs on a bare pipeline agent.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

# tests/common contains many regex strings with invalid escape sequences that
# emit SyntaxWarning at parse time. They are irrelevant to this analysis.
warnings.filterwarnings("ignore", category=SyntaxWarning)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Files that are never migration candidates on their own.
EXCLUDED_BASENAMES = {"__init__.py", "conftest.py", "setup.py"}

# Directory names to skip during repository scanning.
EXCLUDED_DIR_PARTS = {"__pycache__", ".pytest_cache"}

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

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Symbol:
    """A public top-level function, class, or pytest fixture within a candidate module."""

    name: str
    kind: str  # "function", "class", or "fixture"
    lineno: int
    loc: int
    has_docstring: bool
    typed_ratio: float  # 0..1 fraction of annotated params + return
    impacted_tests: List[str] = field(default_factory=list)
    score: float = 0.0
    tier: int = 0
    is_fixture: bool = False


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
    # --- Dependency information (what this module needs) ---
    # Other tests/common modules this module imports directly. Migrating this
    # module cleanly means these must also be migrated (or bridged).
    depends_on_direct: List[str] = field(default_factory=list)
    # Full transitive closure of tests/common modules reached from this module.
    depends_on_transitive: List[str] = field(default_factory=list)
    # --- Impact information (what needs this module) ---
    symbols: List[Symbol] = field(default_factory=list)
    # Test files that import this module directly.
    impacted_tests: List[str] = field(default_factory=list)
    # All files (tests + helpers) that import this module directly.
    impacted_consumers: List[str] = field(default_factory=list)
    # Test files that reach this module directly OR through the common import
    # graph (i.e. they import another common module that imports this one).
    impacted_tests_transitive: List[str] = field(default_factory=list)
    # All files that reach this module directly or transitively.
    impacted_files_transitive: List[str] = field(default_factory=list)
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


def is_pytest_fixture(node: ast.FunctionDef) -> bool:
    """Return True when a top-level function is decorated as a pytest fixture."""
    if node.name.startswith("_"):
        return False
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Name):
                if func.id == "fixture":
                    return True
            elif isinstance(func, ast.Attribute):
                if func.attr == "fixture" and isinstance(func.value, ast.Name):
                    return True
        elif isinstance(decorator, ast.Name):
            if decorator.id == "fixture":
                return True
        elif isinstance(decorator, ast.Attribute):
            if decorator.attr == "fixture":
                return True
    return False


def function_uses_symbol(node: ast.AST, symbol_name: str) -> bool:
    """Return True when a pytest test function uses ``symbol_name`` as an argument."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False

    arg_names = {arg.arg for arg in node.args.posonlyargs}
    arg_names.update(arg.arg for arg in node.args.args)
    arg_names.update(arg.arg for arg in node.args.kwonlyargs)
    if symbol_name in arg_names:
        return True

    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
            if decorator.func.attr == "usefixtures":
                for arg in decorator.args:
                    if isinstance(arg, ast.Constant) and arg.value == symbol_name:
                        return True
    return False


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
# Dependency graph (concrete impact analysis)
# ---------------------------------------------------------------------------


@dataclass
class ImpactGraph:
    """Module-level import graph over tests/common plus external importers."""

    # dotted common module -> repo-relative path.
    dotted_to_rel: Dict[str, str] = field(default_factory=dict)
    # common module -> common modules it imports (forward dependency edges).
    forward: Dict[str, Set[str]] = field(default_factory=dict)
    # common module -> common modules that import it (reverse edges).
    reverse: Dict[str, Set[str]] = field(default_factory=dict)
    # common module -> every file (repo-relative) that imports it directly.
    direct_importers: Dict[str, Set[str]] = field(default_factory=dict)


def build_impact_graph(
    import_index: Dict[str, ConsumerImports], common_abs: str, repo_root: str
) -> ImpactGraph:
    """Build a dependency graph of tests/common modules and their importers."""
    dotted_to_rel: Dict[str, str] = {}
    for abs_path in iter_python_files(common_abs):
        rel = os.path.relpath(abs_path, repo_root).replace(os.sep, "/")
        dotted_to_rel[to_dotted(rel)] = rel
    common_dotted = set(dotted_to_rel)

    forward: Dict[str, Set[str]] = {d: set() for d in common_dotted}
    reverse: Dict[str, Set[str]] = {d: set() for d in common_dotted}
    direct_importers: Dict[str, Set[str]] = {d: set() for d in common_dotted}

    for consumer_rel, imports in import_index.items():
        consumer_dotted = to_dotted(consumer_rel)
        imported_common = {m for m in imports.modules if m in common_dotted}
        for target in imported_common:
            if target == consumer_dotted:
                continue
            direct_importers[target].add(consumer_rel)
            if consumer_dotted in common_dotted:
                forward[consumer_dotted].add(target)
                reverse[target].add(consumer_dotted)

    return ImpactGraph(
        dotted_to_rel=dotted_to_rel,
        forward=forward,
        reverse=reverse,
        direct_importers=direct_importers,
    )


def graph_closure(start: str, edges: Dict[str, Set[str]]) -> Set[str]:
    """Return every node reachable from ``start`` following ``edges``."""
    seen: Set[str] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        for neighbour in edges.get(node, ()):  # noqa: B007
            if neighbour not in seen and neighbour != start:
                seen.add(neighbour)
                stack.append(neighbour)
    return seen


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

    Module score formula:
      score = volume + blast + coupling + quality_gap

      volume = LOC / 40 + (functions + classes) * 1.5
      blast = direct_impacted_tests * 1.2
      coupling = direct_common_deps * 2.0 + transitive_common_deps * 0.3
      quality_gap = (1 - typed_ratio) * 6.0 + (1 - documented_ratio) * 3.0

    The result is rounded to two decimals.
    """
    volume = task.loc / 40.0 + (task.num_functions + task.num_classes) * 1.5
    blast = len(task.impacted_tests) * 1.2
    direct_dep_count = len(task.depends_on_direct)
    transitive_dep_count = max(0, len(task.depends_on_transitive) - direct_dep_count)
    coupling = direct_dep_count * 2.0 + transitive_dep_count * 0.3
    quality_gap = (1.0 - task.typed_ratio) * 6.0 + (1.0 - task.documented_ratio) * 3.0
    return round(volume + blast + coupling + quality_gap, 2)


def compute_symbol_score(symbol: Symbol) -> float:
    """Per-function/class effort score for granular tasks.

    Symbol score formula:
      score = volume + blast + quality_gap

      volume = LOC / 25 + 1.0
      blast = direct_impacted_tests * 1.2
      quality_gap = (1 - typed_ratio) * 3.0 + (0 if docstring else 1.5)

    The result is rounded to two decimals.
    """
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


def analyze_module(
    abs_path: str,
    repo_root: str,
    graph: ImpactGraph,
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
    common2_dotted = "tests.common2." + domain.replace("/", ".")
    if common2_dotted.endswith("."):
        common2_dotted = common2_dotted.rstrip(".")

    symbols: List[Symbol] = []
    typed_values: List[float] = []
    documented = 0
    total_symbols = 0

    for node in tree.body:
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
                fixture = is_pytest_fixture(node)
                tr = typed_ratio_for_function(node)
                kind = "fixture" if fixture else "function"
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
                    is_fixture=kind == "fixture",
                )
            )

    if not symbols:
        return None

    typed_ratio = round(sum(typed_values) / len(typed_values), 2) if typed_values else 0.0
    documented_ratio = round(documented / total_symbols, 2) if total_symbols else 0.0

    # --- Dependency information: what this module needs (forward edges) ---
    def to_rel_list(dotted_names: Set[str]) -> List[str]:
        rels = []
        for name in dotted_names:
            rel_path = graph.dotted_to_rel.get(name)
            # Skip package __init__ nodes: importing a package usually just
            # pulls a submodule, which is already listed separately.
            if rel_path and not rel_path.endswith("__init__.py"):
                rels.append(rel_path)
        return sorted(set(rels))

    deps_direct_dotted = graph.forward.get(dotted, set())
    deps_transitive_dotted = graph_closure(dotted, graph.forward)
    depends_on_direct = to_rel_list(deps_direct_dotted)
    depends_on_transitive = to_rel_list(deps_transitive_dotted)

    # --- Impact information: what needs this module (reverse edges) ---
    dependents_direct = {c for c in graph.direct_importers.get(dotted, set()) if c != rel}
    impacted_consumers = sorted(dependents_direct)
    impacted_tests = sorted(c for c in dependents_direct if is_test_file(c))

    # Transitive: any file that imports this module OR any common module that
    # (transitively) imports this module.
    ancestors = graph_closure(dotted, graph.reverse)
    affected_files: Set[str] = set()
    for node in {dotted} | ancestors:
        affected_files |= graph.direct_importers.get(node, set())
    affected_files.discard(rel)
    impacted_files_transitive = sorted(affected_files)
    impacted_tests_transitive = sorted(f for f in affected_files if is_test_file(f))

    # Attribute impacted tests to individual symbols by name usage.
    consumer_text_cache: Dict[str, str] = {}
    consumer_ast_cache: Dict[str, Optional[ast.Module]] = {}
    for sym in symbols:
        sym_tests: List[str] = []
        for consumer_rel in impacted_tests:
            text = consumer_text_cache.get(consumer_rel)
            if consumer_rel not in consumer_text_cache:
                consumer_abs = os.path.join(repo_root, consumer_rel)
                try:
                    with open(consumer_abs, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    text = ""
                consumer_text_cache[consumer_rel] = text

            if sym.name in text:
                sym_tests.append(consumer_rel)
                continue

            if consumer_rel not in consumer_ast_cache:
                consumer_abs = os.path.join(repo_root, consumer_rel)
                tree = safe_parse(consumer_abs)
                consumer_ast_cache[consumer_rel] = tree

            tree = consumer_ast_cache.get(consumer_rel)
            if tree is None:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("test_"):
                        continue
                    if function_uses_symbol(node, sym.name):
                        sym_tests.append(consumer_rel)
                        break
        sym.impacted_tests = sym_tests

    task = ModuleTask(
        rel_path=rel,
        dotted=dotted,
        domain=domain,
        target_path=target_path,
        loc=loc,
        num_functions=sum(1 for s in symbols if s.kind in {"function", "fixture"}),
        num_classes=sum(1 for s in symbols if s.kind == "class"),
        typed_ratio=typed_ratio,
        documented_ratio=documented_ratio,
        depends_on_direct=depends_on_direct,
        depends_on_transitive=depends_on_transitive,
        symbols=symbols,
        impacted_tests=impacted_tests,
        impacted_consumers=impacted_consumers,
        impacted_tests_transitive=impacted_tests_transitive,
        impacted_files_transitive=impacted_files_transitive,
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
    if max_tier <= 1:
        thresholds: List[float] = []
    else:
        step = len(scores) / max_tier if max_tier else len(scores)
        thresholds = []
        for i in range(1, max_tier):
            index = int(step * i) - 1
            if index < 0:
                index = 0
            elif index >= len(scores):
                index = len(scores) - 1
            thresholds.append(scores[index])

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
    print(f"  Distinct test files impacted (all tasks)  : {total_tests}")
    print(f"  Granular sub-tasks (public funcs/classes/fixtures) : "
          f"{sum(len(t.symbols) for t in tasks)}")
    print(f"  Complexity tiers                          : 1 (easiest) .. {max_tier} (hardest)")
    print()
    print("  How to use this dashboard:")
    print("    * Pick a LOW rank / LOW tier task to start small -- even a single function counts.")
    print("    * 'Tests' = tests importing the module directly; 'Tx' = tests affected transitively")
    print("      (through the common import graph). A big gap between them signals cascade risk.")
    print("    * 'Deps' = other tests/common modules this one imports; migrating cleanly may pull")
    print("      those in too (see the per-module dependency chain below).")
    print("    * 'Target' is the proposed tests/common2 domain path (see DIRECTORY_STRUCTURE.md).")
    print("    * Every migrated function needs type hints, a docstring, and unit tests (>=80% cov).")
    print()

    header = (
        f"{'Rank':>4}  {'Tier':>4}  {'Score':>7}  {'Tests':>5}  {'Tx':>4}  {'Deps':>4}  "
        f"{'LOC':>5}  {'Fns':>3}  {'Typed':>6}  {'UT':>3}  {'Module':<38}  {'Target domain'}"
    )
    print("Migration work queue (easiest first)")
    print("-" * 100)
    print(header)
    print("-" * 100)
    shown = ordered if top is None else ordered[:top]
    for task in shown:
        module_disp = task.rel_path.replace("tests/common/", "")
        if len(module_disp) > 38:
            module_disp = "..." + module_disp[-35:]
        print(
            f"{task.rank:>4}  {task.tier:>4}  {task.score:>7}  "
            f"{len(task.impacted_tests):>5}  {len(task.impacted_tests_transitive):>4}  "
            f"{len(task.depends_on_direct):>4}  {task.loc:>5}  "
            f"{task.num_functions + task.num_classes:>3}  "
            f"{int(task.typed_ratio * 100):>5}%  "
            f"{module_disp:<38}  {task.domain}"
        )
    if top is not None and len(ordered) > top:
        print(f"  ... and {len(ordered) - top} more (increase --top or read the JSON artifact).")
    print()

    # Granular detail for the most approachable tasks.
    detail_count = min(len(shown), 15 if top is None else top)
    print("Granular sub-tasks and full dependency impact for the top approachable modules")
    print("-" * 100)
    for task in shown[:detail_count]:
        print()
        print(f"[Rank {task.rank} | Tier {task.tier} | Score {task.score}] {task.rel_path}")
        print(f"    Proposed target : {task.target_path}")
        print(f"    Type-hint cover : {_bar(task.typed_ratio)} {int(task.typed_ratio * 100)}%   "
              f"Docstrings: {int(task.documented_ratio * 100)}%")

        # Full dependency impact (concrete lists, not a qualitative flag).
        print("    DEPENDS ON (migrate/bridge these too):")
        if task.depends_on_direct:
            for dep in task.depends_on_direct:
                print(f"        <- {dep}")
            extra = [d for d in task.depends_on_transitive if d not in task.depends_on_direct]
            if extra:
                print(f"        (transitively also reaches {len(extra)} more common module(s):)")
                for dep in extra[:8]:
                    print(f"            .. {dep}")
                if len(extra) > 8:
                    print(f"            .. (+{len(extra) - 8} more, see JSON)")
        else:
            print("        (none - self-contained, safe to migrate in isolation)")

        print(
            f"    IMPACT: {len(task.impacted_tests)} test(s) import it directly, "
            f"{len(task.impacted_consumers)} file(s) total; "
            f"{len(task.impacted_tests_transitive)} test(s) affected transitively."
        )

        print(f"    Function-level tasks ({len(task.symbols)}):")
        for sym in sorted(task.symbols, key=lambda s: s.score):
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

    print("=" * 100)
    print("End of dashboard. Machine-readable data is in the YAML artifact (see --yaml-out).")
    print("=" * 100)


def build_json(tasks: List[ModuleTask], max_tier: int) -> dict:
    """Assemble the structured payload for later GitHub Project upload."""
    return {
        "schema_version": 1,
        "summary": {
            "available_modules": len(tasks),
            "distinct_impacted_tests": len({t for task in tasks for t in task.impacted_tests}),
            "distinct_impacted_tests_transitive": len(
                {t for task in tasks for t in task.impacted_tests_transitive}
            ),
            "granular_subtasks": sum(len(t.symbols) for t in tasks),
            "max_tier": max_tier,
        },
        "tasks": [asdict(t) for t in sorted(tasks, key=lambda x: x.rank)],
    }


# ---------------------------------------------------------------------------
# Markdown report emitter (rendered by GitHub Actions as the run "report" via
# $GITHUB_STEP_SUMMARY, and published as a downloadable artifact)
# ---------------------------------------------------------------------------


def _md_cell(value: object) -> str:
    """Escape a value for use inside a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def build_markdown_lines(
    tasks: List[ModuleTask],
    max_tier: int,
    top: Optional[int],
) -> List[str]:
    """Return the dashboard as a human-readable Markdown report."""
    hardest = max_tier
    ordered = sorted(tasks, key=lambda x: x.rank)
    shown = ordered if top is None else ordered[:top]
    distinct_direct = len({t for task in tasks for t in task.impacted_tests})
    distinct_trans = len(
        {t for task in tasks for t in task.impacted_tests_transitive}
    )
    subtasks = sum(len(t.symbols) for t in tasks)

    lines: List[str] = []
    lines.append("# common → common2 Migration Dashboard")
    lines.append("")
    lines.append(
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
        "by `tools/common2_migration/migration_dashboard.py`._"
    )
    lines.append("")

    server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    run_id = os.getenv("GITHUB_RUN_ID", "").strip()
    run_attempt = os.getenv("GITHUB_RUN_ATTEMPT", "").strip()
    if repository and run_id:
        run_url = f"{server}/{repository}/actions/runs/{run_id}"
        if run_attempt:
            run_url += f"/attempts/{run_attempt}"
        lines.append("## Run details")
        lines.append("")
        lines.append(f"- Workflow run: [{run_url}]({run_url})")
        lines.append(
            "- Downloadable artifact: the workflow uploads a bundled artifact named "
            "**migration-dashboard-artifacts** containing the YAML report."
        )
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Modules available to migrate: **{len(tasks)}**")
    lines.append(f"- Distinct tests impacted (direct): **{distinct_direct}**")
    lines.append(f"- Distinct tests impacted (transitive): **{distinct_trans}**")
    lines.append(f"- Granular function/class sub-tasks: **{subtasks}**")
    lines.append("")
    lines.append(
        "**How to read the numbers** (all follow _lower = easier_): "
        f"**rank** = global order 1..{len(tasks)} (rank 1 is the single easiest); "
        f"**tier** = difficulty band 1 (easy) .. {hardest} (hard); "
        "**score** = raw weighted effort (higher = more work)."
    )
    lines.append("")

    heading = "## Migration work queue (easiest first)"
    if top is not None and len(ordered) > top:
        heading += f" — showing top {top} of {len(ordered)}"
    lines.append(heading)
    lines.append("")

    for task in shown:
        module_disp = task.rel_path.replace("tests/common/", "")
        lines.append(f"### {task.rank}. {module_disp}")
        lines.append("")
        lines.append(f"- **Target:** `{_md_cell(task.target_path)}`")
        lines.append(f"- **Domain:** `{_md_cell(task.domain)}`")
        lines.append(f"- **Tier:** {task.tier}")
        lines.append(f"- **Score:** {task.score:.2f}")
        lines.append(f"- **LOC:** {task.loc}")
        lines.append(
            f"- **Size:** {task.num_functions + task.num_classes} function/class/fixture items"
        )
        lines.append(f"- **Typed:** {int(task.typed_ratio * 100)}%")
        lines.append(f"- **Direct tests:** {len(task.impacted_tests)}")
        lines.append(f"- **Transitive tests:** {len(task.impacted_tests_transitive)}")
        lines.append(f"- **Common dependencies:** {len(task.depends_on_direct)}")
        lines.append("")

        deps = task.depends_on_direct or []
        trans = [d for d in task.depends_on_transitive or [] if d not in deps]
        lines.append("#### Dependencies")
        lines.append("")
        if deps:
            lines.append("**Direct dependencies**")
            for dep in deps:
                lines.append(f"- `{_md_cell(dep)}`")
            if trans:
                lines.append("")
                lines.append("**Transitive dependencies**")
                for dep in trans:
                    lines.append(f"- `{_md_cell(dep)}`")
        else:
            lines.append("- None")
        lines.append("")

        direct = task.impacted_tests or []
        tx = task.impacted_tests_transitive or []
        lines.append("#### Impacted tests")
        lines.append("")
        if direct:
            lines.append("**Directly impacted tests**")
            for path in direct:
                lines.append(f"- `{_md_cell(path)}`")
        else:
            lines.append("- No direct test impact recorded")
        if tx:
            lines.append("")
            lines.append("**Transitively impacted tests**")
            for path in tx:
                lines.append(f"- `{_md_cell(path)}`")
        lines.append("")

        if task.symbols:
            lines.append("#### Sub-tasks")
            lines.append("")
            for sym in sorted(task.symbols, key=lambda s: s.score):
                lines.append(
                    f"- [{sym.kind}] `{_md_cell(sym.name)}` — tier {sym.tier}, "
                    f"score {sym.score:.2f}, {sym.loc} LOC"
                )
            lines.append("")
        lines.append("---")
        lines.append("")

    if top is not None and len(ordered) > top:
        lines.append(
            f"_… and {len(ordered) - top} more. Download the YAML/JSON artifact "
            "for the full list and machine-readable details._"
        )
        lines.append("")

    return lines


# ---------------------------------------------------------------------------
# YAML emitter (hand-written so we can embed explanatory comments; no pyyaml
# dependency because the pipeline agent is bare and pyyaml cannot emit comments)
# ---------------------------------------------------------------------------

_YAML_SAFE = re.compile(r"^[A-Za-z0-9_./:@+-]+$")


def _yaml_scalar(value: object) -> str:
    """Render a Python scalar as a safe YAML scalar."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.2f}"
    text = "" if value is None else str(value)
    if text == "":
        return '""'
    if _YAML_SAFE.match(text) and text not in ("true", "false", "null", "~"):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _yaml_list(lines: List[str], key: str, items: List[str], indent: str) -> None:
    """Append a YAML block-sequence (or ``[]`` when empty) for a list of strings."""
    if not items:
        lines.append(f"{indent}{key}: []")
        return
    lines.append(f"{indent}{key}:")
    for item in items:
        lines.append(f"{indent}  - {_yaml_scalar(item)}")


def build_yaml_lines(tasks: List[ModuleTask], max_tier: int) -> List[str]:
    """Return the full commented-YAML dashboard as a list of text lines."""
    hardest = max_tier
    lines: List[str] = []
    lines.append(
        "# ============================================================================"
    )
    lines.append("# common -> common2 Migration Dashboard")
    lines.append("#")
    lines.append("# Score formula")
    lines.append("#   Module score = volume + blast + coupling + quality_gap")
    lines.append("#   volume = LOC/40 + (functions+classes)*1.5")
    lines.append("#   blast = direct impacted tests * 1.2")
    lines.append("#   coupling = direct deps * 2.0 + transitive deps * 0.3")
    lines.append("#   quality_gap = (1 - typed_ratio) * 6.0 + (1 - documented_ratio) * 3.0")
    lines.append("#")
    lines.append("#   Symbol score = volume + blast + quality_gap")
    lines.append("#   volume = LOC/25 + 1.0")
    lines.append("#   blast = direct impacted tests * 1.2")
    lines.append("#   quality_gap = (1 - typed_ratio) * 3.0 + (0 if docstring else 1.5)")
    lines.append("#")
    lines.append("# Field meanings")
    lines.append("#   rank: global ordering; lower is easier")
    lines.append("#   tier: difficulty band; lower is easier")
    lines.append("#   score: weighted effort estimate; higher is more work")
    lines.append("#   depends_on_direct: other tests/common modules this module imports")
    lines.append("#   depends_on_transitive: full import closure reached from here")
    lines.append("#   impacted_tests: tests importing this module directly")
    lines.append("#   impacted_tests_transitive: tests reaching it directly or through the import graph")
    lines.append(
        "# ============================================================================"
    )
    lines.append(
        "# Generated by tools/common2_migration/migration_dashboard.py"
    )
    lines.append("#")
    lines.append("# How to read the difficulty numbers (ALL follow \"lower = easier\"):")
    lines.append("#   rank  : global ordering 1..N across every available module.")
    lines.append("#           rank 1 is the single EASIEST module to migrate. Pick a")
    lines.append("#           low rank for your first contribution.")
    lines.append(f"#   tier  : difficulty band from 1 (easiest) to {hardest} (hardest).")
    lines.append("#           Modules in the same tier are comparable in effort.")
    lines.append("#   score : raw weighted effort estimate (unbounded float, higher =")
    lines.append("#           more work). Derived from lines of code, number of")
    lines.append("#           functions/classes, impacted tests, coupling to other")
    lines.append("#           common modules, and missing typing/docstrings/unit-tests.")
    lines.append("#")
    lines.append("# Each task also lists per-symbol (function/class) sub-tasks with")
    lines.append("# their own rank/tier/score so you can pick a single function instead")
    lines.append("# of a whole module.")
    lines.append("#")
    lines.append("# Dependency & impact fields:")
    lines.append("#   depends_on_direct       : other tests/common modules this module")
    lines.append("#                             imports (usually must migrate too).")
    lines.append("#   depends_on_transitive   : full import closure reached from here.")
    lines.append("#   impacted_tests          : tests importing this module directly.")
    lines.append("#   impacted_tests_transitive: tests reaching it directly OR through")
    lines.append("#                             the common import graph (hidden cascade).")
    lines.append(
        "# ============================================================================"
    )
    lines.append("")
    lines.append("schema_version: 1")
    lines.append("")
    distinct_direct = len({t for task in tasks for t in task.impacted_tests})
    distinct_trans = len(
        {t for task in tasks for t in task.impacted_tests_transitive}
    )
    subtasks = sum(len(t.symbols) for t in tasks)
    lines.append("summary:")
    lines.append(f"  available_modules: {len(tasks)}")
    lines.append(f"  distinct_impacted_tests: {distinct_direct}")
    lines.append(f"  distinct_impacted_tests_transitive: {distinct_trans}")
    lines.append(f"  granular_subtasks: {subtasks}")
    lines.append(f"  max_tier: {hardest}  # tiers range 1 (easy) .. {hardest} (hard)")
    lines.append("")
    lines.append("# Available migration tasks, easiest (rank 1) first.")
    lines.append("tasks:")
    for task in sorted(tasks, key=lambda x: x.rank):
        lines.append("")
        lines.append(
            f"  # ---- rank {task.rank} | tier {task.tier} "
            f"(1=easy..{hardest}=hard) | score {task.score:.2f} ----"
        )
        lines.append(f"  - rank: {task.rank}")
        lines.append(f"    tier: {task.tier}  # 1 = easiest ... {hardest} = hardest")
        lines.append(f"    score: {task.score:.2f}  # raw effort, higher = more work")
        lines.append(f"    module: {_yaml_scalar(task.rel_path)}")
        lines.append(f"    target: {_yaml_scalar(task.target_path)}")
        lines.append(f"    domain: {_yaml_scalar(task.domain)}")
        lines.append(f"    loc: {task.loc}")
        lines.append(f"    num_functions: {task.num_functions}")
        lines.append(f"    num_classes: {task.num_classes}")
        lines.append(f"    typed_ratio: {task.typed_ratio:.2f}")
        lines.append(f"    documented_ratio: {task.documented_ratio:.2f}")
        _yaml_list(lines, "depends_on_direct", task.depends_on_direct, "    ")
        _yaml_list(lines, "depends_on_transitive", task.depends_on_transitive, "    ")
        _yaml_list(lines, "impacted_tests", task.impacted_tests, "    ")
        _yaml_list(
            lines, "impacted_tests_transitive", task.impacted_tests_transitive, "    "
        )
        if not task.symbols:
            lines.append("    symbols: []")
            continue
        lines.append("    symbols:  # bite-sized sub-tasks (pick one function/class)")
        for sym in sorted(task.symbols, key=lambda s: s.score):
            lines.append(f"      - name: {_yaml_scalar(sym.name)}")
            lines.append(f"        kind: {_yaml_scalar(sym.kind)}")
            lines.append(f"        tier: {sym.tier}  # 1 = easiest ... {hardest} = hardest")
            lines.append(f"        score: {sym.score:.2f}")
            lines.append(f"        loc: {sym.loc}")
            lines.append(f"        typed_ratio: {sym.typed_ratio:.2f}")
            lines.append(f"        has_docstring: {_yaml_scalar(sym.has_docstring)}")
            _yaml_list(lines, "impacted_tests", sym.impacted_tests, "        ")
    lines.append("")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def default_repo_root() -> str:
    """Repo root = three levels up from this script (tools/common2_migration)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, os.pardir, os.pardir))


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=default_repo_root(),
                        help="Path to the sonic-mgmt repository root.")
    parser.add_argument("--common-dir", default="tests/common",
                        help="Source directory to scan for migration candidates.")
    parser.add_argument("--tests-dir", default="tests",
                        help="Test tree scanned to compute migration impact.")
    parser.add_argument("--max-tier", type=int, default=5,
                        help="Number of complexity tiers (produces tiers 1..max-tier).")
    parser.add_argument("--top", type=int, default=40,
                        help="Show only the N easiest tasks in the log (0 = all).")
    parser.add_argument("--json-out", default="",
                        help="Optional path to write the machine-readable JSON artifact.")
    parser.add_argument("--yaml-out", default="",
                        help="Optional path to write the commented-YAML dashboard artifact "
                             "(default primary artifact for workflow consumption).")
    parser.add_argument("--markdown-out", default="",
                        help="Optional path to write the Markdown report (GitHub run summary).")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    repo_root = os.path.abspath(args.repo_root)
    common_abs = os.path.join(repo_root, args.common_dir)
    tests_abs = os.path.join(repo_root, args.tests_dir)

    if not os.path.isdir(common_abs):
        print(f"ERROR: common dir not found: {common_abs}", file=sys.stderr)
        return 2

    print(f"Scanning source modules under: {args.common_dir}")
    print(f"Computing impact against test tree: {args.tests_dir}")
    print()

    # 1. Reverse import index + module dependency graph for impact analysis.
    import_index = build_import_index(tests_abs, repo_root)
    graph = build_impact_graph(import_index, common_abs, repo_root)

    # 3. Analyze every candidate module.
    tasks: List[ModuleTask] = []
    for abs_path in iter_python_files(common_abs):
        base = os.path.basename(abs_path)
        if base in EXCLUDED_BASENAMES or is_test_file(base):
            continue
        task = analyze_module(
            abs_path,
            repo_root,
            graph,
        )
        if task is None:
            continue
        tasks.append(task)

    rank_and_score(tasks, args.max_tier)

    top = None if args.top in (0, None) else args.top
    print_dashboard(tasks, args.max_tier, top)

    if args.json_out:
        out_path = args.json_out
        if not os.path.isabs(out_path):
            out_path = os.path.join(repo_root, out_path)
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(build_json(tasks, args.max_tier), handle, indent=2)
        print(f"\nWrote machine-readable dashboard JSON to: {out_path}")

    if args.yaml_out:
        out_path = args.yaml_out
        if not os.path.isabs(out_path):
            out_path = os.path.join(repo_root, out_path)
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(build_yaml_lines(tasks, args.max_tier)))
        print(f"\nWrote commented dashboard YAML to: {out_path}")

    if args.markdown_out:
        out_path = args.markdown_out
        if not os.path.isabs(out_path):
            out_path = os.path.join(repo_root, out_path)
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(
                "\n".join(build_markdown_lines(tasks, args.max_tier, top))
            )
            handle.write("\n")
        print(f"\nWrote Markdown report to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
