"""
conftest_srpto.py — SRPTO pytest plugin
=========================================
Drop this file into your sonic-mgmt root or tests/ directory (or add it to
conftest.py with `pytest_plugins = ['srpto.conftest_srpto']`) to get:

  1. Automatic resource tagging via @pytest.mark.srpto_resources
  2. DUT-level locking at test collection time (not topology-level)
  3. pytest-xdist aware: each worker holds the pool lock

Usage in pytest:
    pytest tests/ \\
        --srpto-testbed testbeds/sonic_t0.yaml \\
        --srpto-resource-map resources.yaml \\
        -n auto                # pytest-xdist parallel workers

Or standalone (without xdist) — SRPTO handles parallelism itself:
    pytest tests/ \\
        --srpto-testbed testbeds/sonic_t0.yaml \\
        --srpto-run-parallel   # SRPTO spawns one subprocess per test file
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Dict, List, Optional

import pytest

logger = logging.getLogger("srpto.conftest")

# ---------------------------------------------------------------------------
# Optional import guard
# ---------------------------------------------------------------------------
try:
    from srpto.lock_manager.dut_lock import DUTPool, ResourceRequirement
    from srpto.resource_tagger.tagger import ResourceTagger
    _SRPTO_AVAILABLE = True
except ImportError:
    _SRPTO_AVAILABLE = False
    logger.warning("[SRPTO] srpto package not found — plugin inactive")


# ---------------------------------------------------------------------------
# Global pool (one per pytest session)
# ---------------------------------------------------------------------------
_pool: Optional[DUTPool] = None
_tagger: Optional[ResourceTagger] = None
_pool_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Custom pytest marker
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "srpto_resources(dut_count, ptf_required, topology_exclusive, "
        "shared_resources, min_topology, dut_names): "
        "SRPTO resource declaration for this test"
    )


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    group = parser.getgroup("srpto", "SRPTO Resource-Aware Parallel Scheduler")
    group.addoption(
        "--srpto-testbed", default="",
        help="Testbed YAML path (required for SRPTO)"
    )
    group.addoption(
        "--srpto-resource-map", default="",
        help="Resource map YAML path (auto-detect if omitted)"
    )
    group.addoption(
        "--srpto-poll-interval", type=float, default=5.0,
        help="DUT pool poll interval in seconds"
    )
    group.addoption(
        "--srpto-acquire-timeout", type=float, default=0.0,
        help="Seconds to wait for DUTs (0 = wait forever)"
    )
    group.addoption(
        "--srpto-run-parallel", action="store_true",
        help="Collect all test files and run them via SRPTO engine (ignores -n)"
    )


# ---------------------------------------------------------------------------
# Session setup
# ---------------------------------------------------------------------------

def pytest_sessionstart(session):
    global _pool, _tagger

    if not _SRPTO_AVAILABLE:
        return

    testbed = session.config.getoption("--srpto-testbed", default="")
    resource_map = session.config.getoption("--srpto-resource-map", default="")
    poll = session.config.getoption("--srpto-poll-interval", default=5.0)
    timeout = session.config.getoption("--srpto-acquire-timeout", default=0.0)

    if not testbed:
        logger.info("[SRPTO] No --srpto-testbed provided — pool not initialised")
        return

    from srpto.scheduler.engine import _parse_testbed
    dut_names, topo_connections, ptf_host = _parse_testbed(testbed)

    if not dut_names:
        logger.warning("[SRPTO] No DUTs found in testbed — SRPTO inactive")
        return

    _pool = DUTPool(
        dut_names=dut_names,
        ptf_host=ptf_host,
        topology_connections=topo_connections,
        poll_interval=poll,
        max_wait_seconds=timeout,
    )
    _tagger = ResourceTagger(resource_map)
    logger.info(
        "[SRPTO] Pool initialised — %d DUT(s): %s", len(dut_names), dut_names
    )


def pytest_sessionfinish(session, exitstatus):
    logger.debug("[SRPTO] Session finished — pool released")


# ---------------------------------------------------------------------------
# Per-test fixture: srpto_duts
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def srpto_duts(request):
    """
    Fixture that acquires DUTs before the test and releases them after.

    Usage in a test:
        @pytest.mark.srpto_resources(dut_count=2, min_topology=["D1D2:2"])
        def test_bgp_gr(srpto_duts, duthosts, tbinfo):
            dut1, dut2 = srpto_duts  # actual testbed device names
            ...
    """
    if _pool is None or _tagger is None:
        yield []
        return

    # Get resource requirement from marker or auto-detect
    marker = request.node.get_closest_marker("srpto_resources")
    if marker:
        from srpto.resource_tagger.tagger import parse_link_requirements
        raw = {
            "dut_count":          marker.kwargs.get("dut_count", 1),
            "ptf_required":       marker.kwargs.get("ptf_required", False),
            "topology_exclusive": marker.kwargs.get("topology_exclusive", False),
            "shared_resources":   marker.kwargs.get("shared_resources", []),
            "min_topology":       marker.kwargs.get("min_topology", []),
            "dut_names":          marker.kwargs.get("dut_names", []),
        }
        req = _tagger._from_dict(raw)
    else:
        # Auto-detect from test source
        source = None
        try:
            import inspect
            source = inspect.getsource(request.node.obj)
        except Exception:
            pass
        req = _tagger.get_requirement(request.node.fspath.strpath, source)

    script_name = request.node.nodeid
    allocated = _pool.acquire(req, script_name)

    if allocated is None:
        pytest.fail(
            f"[SRPTO] Could not acquire {req.dut_count} DUT(s) for {script_name}"
        )

    try:
        yield allocated
    finally:
        _pool.release(allocated, script_name, req)


# ---------------------------------------------------------------------------
# --srpto-run-parallel mode: collect test files, delegate to engine
# ---------------------------------------------------------------------------

def pytest_collection_finish(session):
    """
    When --srpto-run-parallel is set, hand off all collected test file paths
    to the SRPTO engine and exit pytest (bypass xdist).
    """
    if not _SRPTO_AVAILABLE:
        return
    if not session.config.getoption("--srpto-run-parallel", default=False):
        return

    testbed = session.config.getoption("--srpto-testbed", default="")
    resource_map = session.config.getoption("--srpto-resource-map", default="")

    # Collect unique test file paths
    script_paths = list(dict.fromkeys(
        str(item.fspath) for item in session.items
    ))

    logger.info(
        "[SRPTO] --srpto-run-parallel: handing %d file(s) to engine",
        len(script_paths)
    )

    from srpto.scheduler.engine import ParallelScheduler, SchedulerConfig
    cfg = SchedulerConfig(
        testbed_path=testbed,
        resource_map_path=resource_map,
        mode="pytest",
    )
    scheduler = ParallelScheduler(cfg)
    results = scheduler.run(script_paths)

    # Report back through pytest
    failed = [r for r in results if r.status == "failed"]
    if failed:
        pytest.exit(
            f"SRPTO: {len(failed)} script(s) failed: "
            + ", ".join(os.path.basename(r.script_path) for r in failed),
            returncode=1,
        )
    else:
        pytest.exit("SRPTO: All scripts passed", returncode=0)
