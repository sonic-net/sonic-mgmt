# DASH API load-speed test: render per-ENI private-link config, push via gNMI, report per-ENI/total time + memory.
# Scale via OVERRIDE_* below; see test_dash_api_speed_pl.md.
import fnmatch
import importlib.util
import logging
import os
import shutil
import sys
import tempfile
import time

import pytest
from dash_api_speed_common import (
    _collect_memory,
    _collect_redis_memory,
    _print_per_eni_load_times,
    _print_results,
    cleanup_config_via_gnmi,
    load_config_via_gnmi,
)

# ── Scale overrides: int to override, None for the default ───────────────────
OVERRIDE_ENI_COUNT = None        # None -> per-NPU-hwsku default below
OVERRIDE_MAPPING_COUNT = None    # mappings per ENI; None -> 64K
OVERRIDE_ROUTE_COUNT = None      # routes per ENI; None -> 10K
CLEANUP_AFTER = True             # delete this run's config afterwards; False keeps it
CLEANUP_MODE = "precise"         # "precise" (gNMI DELETE each file) or "flushdb" (instant, wipes all DPU_APPL_DB)
MEM_TIMELINE_EVERY = 1           # sample free -m every Nth file (1=every file; higher=faster, fewer points)
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_ENI_COUNT_BY_HWSKU = {"Mellanox-SN4280-O28": 64, "Cisco-8102-28FH-DPU-O": 32}
_DEFAULT_MAPPING_COUNT = 64 * 1000
_DEFAULT_ROUTE_COUNT = 10 * 1000

# Load render.py as a module so its multiprocessing workers can pickle its funcs.
_RENDER_PATH = os.path.join(os.path.dirname(__file__), "configs", "dash_api_speed_pl", "render.py")
_render_spec = importlib.util.spec_from_file_location("dash_render", _RENDER_PATH)
render = importlib.util.module_from_spec(_render_spec)
sys.modules["dash_render"] = render
_render_spec.loader.exec_module(render)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("smartswitch"),
    pytest.mark.skip_check_dut_health,
    pytest.mark.disable_loganalyzer,
    pytest.mark.sanity_check(skip_sanity=True),
]


def _resolve_scale(npu_hwsku):
    # Resolve (eni_count, mapping_count, route_count) from overrides + hwsku.
    eni_count = OVERRIDE_ENI_COUNT or _DEFAULT_ENI_COUNT_BY_HWSKU.get(npu_hwsku)
    assert eni_count, ("No default ENI count for NPU hwsku %r — set OVERRIDE_ENI_COUNT (known: %s)."
                       % (npu_hwsku, ", ".join(_DEFAULT_ENI_COUNT_BY_HWSKU)))
    return eni_count, OVERRIDE_MAPPING_COUNT or _DEFAULT_MAPPING_COUNT, OVERRIDE_ROUTE_COUNT or _DEFAULT_ROUTE_COUNT


def _build_render_params(eni_count, mapping_count, route_count):
    # Map per-ENI scale knobs onto render.DEFAULTS for one DPU; print actual map/route counts.
    # Decomposition may under-shoot; return params.
    p = dict(render.DEFAULTS)
    p["DPUS"] = 1
    p["ENI_COUNT"] = eni_count
    p["MINIMAL_SINGLE_ENTRY"] = False
    nsg_groups = p["ACL_NSG_COUNT"] * 2
    p["ACL_RULES_NSG"] = max(2, 2 * (mapping_count // nsg_groups))
    p["ACL_MAPPED_PER_NSG"] = p["ACL_RULES_NSG"]
    p["TOTAL_OUTBOUND_ROUTES"] = route_count * eni_count

    actual_maps = nsg_groups * (p["ACL_RULES_NSG"] // 2)
    per_eni_routes = p["TOTAL_OUTBOUND_ROUTES"] // p["ENI_COUNT"]
    # +1: the eni template emits an extra local_ip/32 route beyond the decomposed set.
    actual_routes = len(list(render.compute_outbound_routes(
        render.ip2int(p["IP_R_START"]), 0, p, per_eni_routes))) + 1
    print("Render scale: ENI_COUNT=%d, mappings/ENI=%d (requested %d), routes/ENI=%d (requested %d)"
          % (eni_count, actual_maps, mapping_count, actual_routes, route_count))
    return p


def _assert_programmed(counts, eni_count):
    # Require exact: landed (DBSIZE delta) == sent SET ops (no KEYS scan; load polls for async-commit settle first).
    landed = counts.get("landed", 0)
    expected = counts.get("expected_total", 0)
    per_table = counts.get("per_table", {})
    rendered_enis = per_table.get("DASH_ENI_TABLE", 0)
    print("Programmed (DPU_APPL_DB): landed %d keys vs %d SET ops sent [%s]"
          % (landed, expected, ", ".join("%s=%d" % (t, per_table[t]) for t in sorted(per_table))))
    missing = []
    if rendered_enis != eni_count:
        missing.append("rendered ENIs %d != %d" % (rendered_enis, eni_count))
    if landed != expected:
        missing.append("landed %d != %d sent" % (landed, expected))
    assert not missing, "DASH config not exactly programmed in DPU_APPL_DB: " + "; ".join(missing)


def test_dash_api_speed_pl(localhost, duthost, dpuhosts, dpu_index, creds):
    # Render DASH config, push it via gNMI, report per-ENI/total time + memory.
    dpuhost = dpuhosts[dpu_index]
    npu_hwsku = duthost.facts.get("hwsku", "unknown")
    dpu_hwsku = dpuhost.facts.get("hwsku", "unknown")
    print("\n==================== DASH API SPEED PL ====================")
    print("NPU host   : %s\nNPU hwsku  : %s" % (duthost.hostname, npu_hwsku))
    print("DPU index  : %s\nDPU host   : %s\nDPU hwsku  : %s" % (dpu_index, dpuhost.hostname, dpu_hwsku))
    print("===========================================================")
    logger.info("NPU host=%s hwsku=%s ; DPU[%s] host=%s hwsku=%s",
                duthost.hostname, npu_hwsku, dpu_index, dpuhost.hostname, dpu_hwsku)

    eni_count, mapping_count, route_count = _resolve_scale(npu_hwsku)
    print("Scale: ENIs=%d, mappings/ENI=%d, routes/ENI=%d (override None => hwsku/default; full-scale is slow)"
          % (eni_count, mapping_count, route_count))

    # Render under the repo so the host docker daemon can bind-mount it (/tmp isn't shared).
    render_output_dir = tempfile.mkdtemp(prefix="dash_cfg_", dir=os.path.dirname(os.path.abspath(__file__)))
    logger.info("Rendering DASH configs into %s", render_output_dir)
    params = _build_render_params(eni_count, mapping_count, route_count)
    render_start = time.time()
    render.generate(params, render_output_dir, prefix="pl_100")
    render_elapsed = time.time() - render_start

    # render always emits "dpu0" (DPUS=1); the push targets real hardware via the client's -i <dpu_index>.
    config_dir = os.path.join(render_output_dir, "dpu0")
    assert os.path.isdir(config_dir), f"Config directory not found after render: {config_dir}"
    files = sorted(f for f in os.listdir(config_dir) if fnmatch.fnmatch(f, "*dpu0*.json"))
    assert files, f"No JSON config files found in {config_dir}"
    print("Rendered %d config files to push to hardware DPU%d" % (len(files), dpuhost.dpu_index))

    mem_before = {"NPU": _collect_memory(duthost), "DPU": _collect_memory(dpuhost)}
    redis_before = _collect_redis_memory(dpuhost)

    timings, mem_timeline = {}, []
    total_start = time.time()
    try:
        counts = load_config_via_gnmi(localhost, duthost, dpuhost, config_dir, files, creds,
                                      timings, mem_timeline, mem_every=MEM_TIMELINE_EVERY)
        _assert_programmed(counts, eni_count)
    finally:
        total_elapsed = time.time() - total_start  # measurement window (cleanup not counted)
        try:
            mem_after = {"NPU": _collect_memory(duthost), "DPU": _collect_memory(dpuhost)}
            redis_after = _collect_redis_memory(dpuhost)
            _print_per_eni_load_times(timings, total_elapsed)
            _print_results(timings, total_elapsed, mem_before, mem_after, redis_before, redis_after, mem_timeline)
        except Exception:
            logger.exception("Failed to collect/print post-test results")

        # Tear down this run's config (needs the rendered files, so before rmtree).
        cleanup_elapsed = 0.0
        if CLEANUP_AFTER:
            try:
                cleanup_start = time.time()
                cleanup_config_via_gnmi(localhost, duthost, dpuhost, config_dir, files, creds, mode=CLEANUP_MODE)
                cleanup_elapsed = time.time() - cleanup_start
            except Exception:
                logger.exception("Post-test cleanup failed (non-fatal)")

        shutil.rmtree(render_output_dir, ignore_errors=True)
        logger.info("Cleaned up rendered config dir: %s", render_output_dir)

        # Phase breakdown (excludes pytest fixture setup/teardown overhead).
        print("\n  PHASE BREAKDOWN (s): render=%.1f  push+verify=%.1f  cleanup=%.1f  total=%.1f"
              % (render_elapsed, total_elapsed, cleanup_elapsed,
                 render_elapsed + total_elapsed + cleanup_elapsed))
