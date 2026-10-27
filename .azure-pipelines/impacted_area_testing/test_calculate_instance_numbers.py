"""Regression tests for the per-topology test-script selection pipeline step."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


def _encode_bytes(payload: bytes) -> str:
    return base64.b64encode(gzip.compress(payload)).decode("ascii")


def _encode_payload(payload: object) -> str:
    return _encode_bytes(json.dumps(payload).encode("utf-8"))


def _run_step(tmp_path: Path, payload: str, topology: str = "t2") -> subprocess.CompletedProcess[str]:
    template = yaml.safe_load(
        Path(__file__).with_name("calculate-instance-numbers.yml").read_text(encoding="utf-8")
    )
    script = template["steps"][0]["script"].replace("${{ parameters.TOPOLOGY }}", topology)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").symlink_to(sys.executable)
    return subprocess.run(
        ["/bin/bash", "-c", script],
        env={"PATH": str(bin_dir), "TEST_SCRIPTS": payload},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("topology", ["t2", "dualtor-aa-vpp", "t1-multi-asic"])
def test_exports_scripts_without_package_manager_or_jq(tmp_path: Path, topology: str) -> None:
    """Run the actual YAML step with only Python available on PATH."""
    scripts = {
        "t0_checker": ["acl/test_acl.py"],
        "t2_checker": ["bgp/test_second.py", "bgp/test_first.py"],
        "dualtor-aa-vpp_checker": ["dualtor/test_tunnel.py"],
        "t1-multi-asic_checker": ["bgp/test_multi_asic.py"],
    }

    result = _run_step(tmp_path, _encode_payload(scripts), topology)

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout == (
        "TEST_SCRIPTS script count per checker:\n"
        "  t0_checker: 1\n"
        "  t2_checker: 2\n"
        "  dualtor-aa-vpp_checker: 1\n"
        "  t1-multi-asic_checker: 1\n"
        f"##vso[task.setvariable variable=SCRIPTS]{','.join(scripts[f'{topology}_checker'])}"
    )


def test_accepts_large_compressed_payload(tmp_path: Path) -> None:
    """Keep handling metadata larger than the agent's 40 KiB output-line limit."""
    scripts = {
        "t0_checker": [f"acl/test_{index:05d}.py" for index in range(3000)],
        "t2_checker": ["bgp/test_bgp.py"],
    }
    assert len(json.dumps(scripts)) > 40 * 1024

    result = _run_step(tmp_path, _encode_payload(scripts))

    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "TEST_SCRIPTS script count per checker:\n"
        "  t0_checker: 3000\n"
        "  t2_checker: 1\n"
        "##vso[task.setvariable variable=SCRIPTS]bgp/test_bgp.py"
    )


def test_preserves_empty_script_list(tmp_path: Path) -> None:
    """Export an empty variable when a checker explicitly has no scripts."""
    result = _run_step(tmp_path, _encode_payload({"t2_checker": []}))

    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("##vso[task.setvariable variable=SCRIPTS]")


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "not-base64!",
        base64.b64encode(b"not gzip").decode("ascii"),
        base64.b64encode(gzip.compress(b"{}")[:-4]).decode("ascii"),
        _encode_bytes(b"{invalid JSON"),
    ],
)
def test_rejects_corrupted_payload(tmp_path: Path, payload: str) -> None:
    """Fail the task without publishing a successful output for invalid input."""
    result = _run_step(tmp_path, payload)

    assert result.returncode != 0
    assert result.stderr
    assert "##vso[task.setvariable" not in result.stdout


def test_rejects_missing_checker(tmp_path: Path) -> None:
    """Surface a missing checker rather than publishing an empty script list."""
    result = _run_step(tmp_path, _encode_payload({"t0_checker": []}))

    assert result.returncode != 0
    assert "t2_checker" in result.stderr
    assert "##vso[task.setvariable" not in result.stdout


@pytest.mark.parametrize("payload", [[], None, "scripts"])
def test_rejects_non_object_payload(tmp_path: Path, payload: object) -> None:
    """Require the decoded payload to be a checker-to-scripts mapping."""
    result = _run_step(tmp_path, _encode_payload(payload))

    assert result.returncode != 0
    assert "TEST_SCRIPTS must be a JSON object" in result.stderr
    assert "##vso[task.setvariable" not in result.stdout


@pytest.mark.parametrize("scripts", ["bgp/test_bgp.py", None, {}, [1], ["bgp/test_bgp.py", None]])
def test_rejects_invalid_script_list(tmp_path: Path, scripts: object) -> None:
    """Reject invalid script lists instead of joining strings or non-string values."""
    result = _run_step(tmp_path, _encode_payload({"t2_checker": scripts}))

    assert result.returncode != 0
    assert "Expected a list of test scripts for t2_checker" in result.stderr
    assert "##vso[task.setvariable" not in result.stdout
