#!/usr/bin/env python3
"""
srpto_run.py — SRPTO CLI entry point
======================================
Drop-in parallel scheduler for sonic-mgmt / spytest.

Usage examples:

  # Run three tests in parallel on a 4-DUT testbed
  python -m srpto.cli.srpto_run \\
      --testbed testbeds/sonic_t0_4dut.yaml \\
      --scripts tests/bgp/test_bgp_gr.py tests/acl/test_acl.py tests/snmp/test_snmp.py \\
      --resource-map resources.yaml \\
      --mode spytest

  # Auto-generate a resource-map YAML from scripts (then edit + re-run)
  python -m srpto.cli.srpto_run \\
      --testbed testbeds/sonic_t0.yaml \\
      --scripts tests/bgp/test_bgp_gr.py tests/acl/test_acl.py \\
      --generate-resource-map resources_auto.yaml

  # Dry-run — resolve allocations only, no subprocess launched
  python -m srpto.cli.srpto_run \\
      --testbed testbeds/sonic_t0.yaml \\
      --scripts tests/*.py \\
      --resource-map resources.yaml \\
      --dry-run

  # Pytest mode (sonic-mgmt community tests)
  python -m srpto.cli.srpto_run \\
      --testbed testbeds/sonic_t0.yaml \\
      --scripts tests/bgp/ tests/acl/ \\
      --mode pytest
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
from typing import List

# Ensure srpto package is importable when run from the sonic-mgmt root
_HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from srpto.scheduler.engine import ParallelScheduler, SchedulerConfig
from srpto.resource_tagger.tagger import ResourceTagger


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(level: str):
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        handlers=[logging.StreamHandler(sys.stderr)],
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="srpto_run",
        description="SRPTO — SONiC Resource-Aware Parallel Test Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Required / main args
    p.add_argument(
        "--testbed", "-t", required=True,
        help="Path to testbed YAML (sonic-mgmt or spytest format)"
    )
    p.add_argument(
        "--scripts", "-s", nargs="+",
        help="Script paths or glob patterns to run (e.g. tests/bgp/*.py)"
    )
    p.add_argument(
        "--resource-map", "-r", default="",
        help="Path to SRPTO resource-map YAML (auto-detect if omitted)"
    )

    # Invocation mode
    p.add_argument(
        "--mode", choices=["spytest", "pytest"], default="spytest",
        help="Invocation mode: spytest (default) or pytest (sonic-mgmt community)"
    )

    # Execution options
    p.add_argument("--logs-dir", default="./srpto_logs", help="Log output directory")
    p.add_argument("--max-workers", type=int, default=16, help="Max parallel workers")
    p.add_argument(
        "--acquire-timeout", type=float, default=0.0,
        help="Seconds to wait for DUTs (0 = wait forever, same as Eka default)"
    )
    p.add_argument("--poll-interval", type=float, default=5.0,
                   help="DUT pool poll interval in seconds")
    p.add_argument("--dry-run", action="store_true",
                   help="Resolve allocations only, do not launch subprocesses")
    p.add_argument("--spytest-bin", default="",
                   help="Explicit path to spytest binary")
    p.add_argument("--pytest-bin", default="pytest",
                   help="pytest binary (default: pytest)")
    p.add_argument("--extra-args", nargs="*", default=[],
                   help="Extra arguments appended to every script invocation")

    # Resource map generation
    p.add_argument(
        "--generate-resource-map", metavar="OUT_YAML",
        help="Auto-generate resources.yaml from script analysis, then exit"
    )

    # Output / logging
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="Log level (default: INFO)")
    p.add_argument("--json-results", metavar="OUT_JSON",
                   help="Write results to a JSON file after completion")
    p.add_argument("--stream-json", action="store_true",
                   help="Print the raw {\"type\":\"queue_state\",...} JSON line to "
                        "stdout on every status change, for a CI/UI consumer to parse. "
                        "Default: a clean [POOL] free/busy line instead.")

    return p


# ---------------------------------------------------------------------------
# Script expansion (glob support)
# ---------------------------------------------------------------------------

def _expand_scripts(raw: List[str]) -> List[str]:
    """Expand glob patterns and directories into individual script files."""
    result = []
    for pattern in raw:
        if "*" in pattern or "?" in pattern:
            matched = glob.glob(pattern, recursive=True)
            result.extend(sorted(m for m in matched if m.endswith(".py")))
        elif os.path.isdir(pattern):
            for root, _, files in os.walk(pattern):
                for f in sorted(files):
                    if f.startswith("test_") and f.endswith(".py"):
                        result.append(os.path.join(root, f))
        else:
            result.append(pattern)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.log_level)

    scripts = _expand_scripts(args.scripts or [])
    if not scripts and not args.generate_resource_map:
        parser.error("No scripts specified (--scripts)")

    # ── Generate resource map and exit ─────────────────────────────────────
    if args.generate_resource_map:
        tagger = ResourceTagger()
        yaml_content = tagger.generate_resource_map_yaml(scripts)
        with open(args.generate_resource_map, "w") as f:
            f.write(yaml_content)
        print(
            f"[SRPTO] Resource map written to: {args.generate_resource_map}\n"
            f"        Review and adjust dut_count, shared_resources, and topology_exclusive\n"
            f"        fields before running."
        )
        return 0

    # ── Build scheduler config ──────────────────────────────────────────────
    cfg = SchedulerConfig(
        testbed_path=args.testbed,
        resource_map_path=args.resource_map,
        logs_dir=args.logs_dir,
        max_workers=args.max_workers,
        acquire_timeout=args.acquire_timeout,
        poll_interval=args.poll_interval,
        mode=args.mode,
        extra_args=args.extra_args or [],
        spytest_bin=args.spytest_bin,
        pytest_bin=args.pytest_bin,
        dry_run=args.dry_run,
        stream_json=args.stream_json,
    )

    # ── Run ─────────────────────────────────────────────────────────────────
    print(f"[SRPTO] Starting {len(scripts)} script(s) on testbed: {args.testbed}")
    if args.dry_run:
        print("[SRPTO] DRY-RUN mode — no subprocesses will be launched")

    scheduler = ParallelScheduler(cfg)
    results = scheduler.run(scripts)

    # ── Write JSON results ──────────────────────────────────────────────────
    if args.json_results:
        data = [
            {
                "script": r.script_path,
                "status": r.status,
                "duts": r.duts_allocated,
                "return_code": r.return_code,
                "duration_s": r.duration_s,
                "log_path": r.log_path,
                "error": r.error,
            }
            for r in results
        ]
        with open(args.json_results, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[SRPTO] Results written to: {args.json_results}")

    # Exit code: 0 if all done, 1 if any failed, 1 if EVERYTHING was skipped
    # (a run where every script was rejected as topology-infeasible up front
    # is a misconfigured invocation, not a clean pass — it should not report
    # exit 0 just because nothing technically "failed").
    failed = [r for r in results if r.status == "failed"]
    skipped = [r for r in results if r.status == "skipped"]
    if failed:
        return 1
    if results and len(skipped) == len(results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
