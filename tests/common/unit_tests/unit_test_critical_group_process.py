"""Exercise critical-process batch handling without testbed dependencies.

Run from the repository root with::

    python -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_critical_group_process.py -q
"""

import ast
from collections.abc import Mapping
import logging
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "devices" / "sonic.py"
COMMAND = ('docker exec swss bash -c "[ -f /etc/supervisor/critical_processes ]'
           ' && cat /etc/supervisor/critical_processes"')
DEFINITIONS = {"swss": {"groups": ["syncd"], "processes": ["orchagent"]}}


@pytest.fixture
def host():
    tree = ast.parse(MODULE_PATH.read_text())
    sonic_host = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SonicHost"
    )
    methods = [
        node for node in sonic_host.body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("critical_group_process", "_retry_if_oci_exec_race")
    ]
    namespace = {
        "Mapping": Mapping,
        "logging": logging,
        "re": re,
        "time": SimpleNamespace(sleep=Mock()),
    }
    exec(compile(ast.Module(body=methods, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    instance = SimpleNamespace(
        hostname="dut",
        critical_services=["swss"],
        _os_version="202608",
        shell_cmds=Mock(),
        shell=Mock(),
        sleep=namespace["time"].sleep,
    )
    for method in methods:
        setattr(instance, method.name, namespace[method.name].__get__(instance))
    return instance


def command_result(rc=0, stdout="group:syncd\nprogram:orchagent", stderr=""):
    return {
        "cmd": COMMAND,
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_lines": stdout.splitlines(),
    }


@pytest.mark.parametrize("failed", [False, True])
def test_valid_results_are_parsed(host, failed):
    """Parse valid results regardless of the aggregate failure flag."""
    host.shell_cmds.return_value = {"failed": failed, "results": [command_result()]}

    assert host.critical_group_process() == DEFINITIONS
    host.shell_cmds.assert_called_once_with(
        cmds=[COMMAND], continue_on_fail=True, module_ignore_errors=True, timeout=30
    )
    host.shell.assert_not_called()


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_failed_batch_retries_oci_race(host, stream):
    """Recover an OCI race even when shell_cmds marks the batch failed."""
    output = {"stdout": "", "stderr": ""}
    output[stream] = "OCI runtime exec failed: unable to start: starting setns process"
    host.shell_cmds.return_value = {
        "failed": True,
        "msg": "At least running one of the commands failed",
        "results": [command_result(rc=127, **output)],
    }
    host.shell.return_value = command_result()

    assert host.critical_group_process() == DEFINITIONS
    host.shell.assert_called_once_with(COMMAND, module_ignore_errors=True)
    host.sleep.assert_called_once_with(2)


@pytest.mark.parametrize("oci_race", [False, True])
def test_persistent_command_failure_is_not_parsed(host, oci_race):
    """Keep nonzero command results unavailable after any bounded retries."""
    result = command_result(
        rc=127 if oci_race else 1,
        stdout="OCI runtime exec failed: starting setns process" if oci_race else "",
    )
    host.shell_cmds.return_value = {"failed": True, "results": [result]}
    host.shell.return_value = result

    assert host.critical_group_process() == {}
    assert host.shell.call_count == (3 if oci_race else 0)


@pytest.mark.parametrize("response", [
    {"failed": True, "msg": "Privilege escalation timed out"},
    {"failed": True, "results": None},
    {"results": {}},
    {"results": "invalid"},
    {"unreachable": True, "msg": "Host unreachable", "results": []},
])
def test_invalid_batch_preserves_error(host, response):
    """Reject unavailable batches while preserving the original error."""
    host.shell_cmds.return_value = response
    message = response.get("msg", "shell_cmds returned no valid results list")

    with pytest.raises(RuntimeError, match=re.escape(
        "Unable to read critical process definitions on dut: " + message
    )):
        host.critical_group_process()
    host.shell.assert_not_called()
