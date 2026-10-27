"""Regression tests for jq acquisition in the test-script selection step."""

import base64
import gzip
import json
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest
import yaml


@pytest.mark.parametrize("topology", ["t2", "dualtor-aa-vpp"])
@pytest.mark.parametrize("jq_installed,install_exit", [(True, 100), (False, 0), (False, 100)])
def test_get_test_scripts_jq_dependency(tmp_path, topology, jq_installed, install_exit):
    """Reuse preinstalled jq, install it when missing, and fail immediately if installation fails."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for command in ("base64", "gunzip", "gzip", "rm"):
        executable = shutil.which(command)
        assert executable, "{} is required to run the pipeline step".format(command)
        (bin_dir / command).symlink_to(executable)

    jq = shutil.which("jq")
    assert jq, "jq is required to exercise the pipeline queries"
    if jq_installed:
        (bin_dir / "jq").symlink_to(jq)

    apt_log = tmp_path / "apt.log"
    sudo = bin_dir / "sudo"
    sudo.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(apt_log))}\n"
        "case \" $* \" in\n"
        "  *' install jq '*)\n"
        f"    [ {install_exit} -eq 0 ] || exit {install_exit}\n"
        f"    /bin/ln -s {shlex.quote(jq)} {shlex.quote(str(bin_dir / 'jq'))}\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n"
    )
    sudo.chmod(0o755)

    template = yaml.safe_load(Path(__file__).with_name("calculate-instance-numbers.yml").read_text())
    scripts_json = tmp_path / "ts.json"
    script = template["steps"][0]["script"]
    script = script.replace("${{ parameters.TOPOLOGY }}", topology)
    script = script.replace("/tmp/ts.json", shlex.quote(str(scripts_json)))
    scripts = ["bgp/test_one.py", "bgp/test_two.py"]
    payload = json.dumps({topology + "_checker": scripts}).encode()
    result = subprocess.run(
        ["/bin/bash", "-c", script],
        cwd=str(tmp_path),
        env={
            "PATH": str(bin_dir),
            "BASH_ENV": "/dev/null",
            "TEST_SCRIPTS": base64.b64encode(gzip.compress(payload)).decode(),
        },
        capture_output=True,
        text=True,
        timeout=10,
    )

    expected_exit = 0 if jq_installed else install_exit
    assert result.returncode == expected_exit, result.stderr
    if jq_installed:
        assert not apt_log.exists(), apt_log.read_text()
    else:
        assert "install jq" in apt_log.read_text()
    if expected_exit == 0:
        assert result.stdout.splitlines()[-1] == "##vso[task.setvariable variable=SCRIPTS]" + ",".join(scripts)
    else:
        assert not scripts_json.exists()
        assert "jq: command not found" not in result.stderr
