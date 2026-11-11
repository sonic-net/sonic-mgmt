"""Deployment-only Generic smoke; generated pytest/L1/MMU facts are separate work."""

import json
import logging
import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = [pytest.mark.topology("generic"), pytest.mark.disable_loganalyzer]


@pytest.fixture(scope="session")
def generic_deployment_lifecycle(tbinfo):
    """Restore originals after the global module config/core guard finishes."""
    root = Path(__file__).resolve().parents[2]
    workspace = root / ".generic_hwsku" / tbinfo["conf-name"]
    invocation = json.loads((workspace / "invocation.json").read_text())
    assert invocation["testbed"] == tbinfo["conf-name"], "Frozen Generic invocation names a different testbed"

    def run_phase(action):
        command = [sys.executable, str(root / "ansible" / "scripts" / "generic_hwsku_lifecycle.py"),
                   "--action", action, "--workspace", str(workspace)]
        for key, value in invocation.items():
            command.extend(["--" + key.replace("_", "-"), value])
        log_path = workspace / ("pytest-" + action + ".log")
        descriptor = os.open(str(log_path), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as log:
            completed = subprocess.run(
                command, cwd=str(root / "ansible"), stdout=log, stderr=subprocess.STDOUT, check=False)
        assert completed.returncode == 0, "Generic {} failed (rc {}); private evidence: {}".format(
            action, completed.returncode, log_path)

    try:
        yield workspace, run_phase
    finally:
        run_phase("remove-topo")
        restored = json.loads((workspace / "deployment-report.json").read_text())
        assert restored["status"] == "RESTORED" and restored["restoration_verified"], (
            "Generic recovery was not verified; retain this platform reservation")
        logging.getLogger(__name__).info("GENERIC_RECOVERY_VERIFIED %s", restored["bundle_sha256"])


def test_frozen_generic_deployment_smoke(generic_deployment_lifecycle):
    workspace, run_phase = generic_deployment_lifecycle
    run_phase("smoke")
    report = json.loads((workspace / "deployment-report.json").read_text())
    assert report["status"] == "SMOKE_PASSED", "Missing independently verified Generic smoke result"
    summary = {key: report[key] for key in (
        "status", "scenario_id", "source_sha", "bundle_sha256", "traffic_executed", "traffic_status",
        "qualification_pass", "coverage_complete", "coverage_warnings")}
    summary["applied_health"] = {
        device: {key: result.get(key) for key in (
            "ready", "ports", "applied_buffer_bindings", "reserved_headroom")}
        for device, result in report["health"].items()}
    logging.getLogger(__name__).info("GENERIC_VERIFIED_CONFIGURATION %s", json.dumps(summary, sort_keys=True))
