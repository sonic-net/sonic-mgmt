"""Focused unit tests for MACsec service readiness across neighbor runtimes."""

import ast
from collections import UserDict
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import MagicMock


class FakeCsonicHost:
    pass


class FakeEosHost:
    pass


MODULE_PATH = Path(__file__).resolve().parents[2] / "macsec/macsec_config_helper.py"
SOURCE = MODULE_PATH.read_text()
TREE = ast.parse(SOURCE)
FUNCTION_NAMES = {
    "_command_succeeded",
    "_command_output_lines",
    "_unique_macsec_neighbor_hosts",
    "_macsec_service_ready",
    "_command_diagnostic",
    "_macsec_service_diagnostics",
    "_start_csonic_macsec_service",
    "_stop_csonic_macsec_service",
    "enable_macsec_feature",
    "disable_macsec_feature",
}
NODES = [
    node for node in TREE.body
    if (
        isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES
    ) or (
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "CSONIC_MACSEC_SUPERVISOR_CONFIG"
            for target in node.targets
        )
    )
]
NAMESPACE = {
    "CsonicHost": FakeCsonicHost,
    "EosHost": FakeEosHost,
    "Mapping": Mapping,
    "logger": MagicMock(),
}
exec(compile(ast.Module(body=NODES, type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)

_command_output_lines = NAMESPACE["_command_output_lines"]
_unique_macsec_neighbor_hosts = NAMESPACE["_unique_macsec_neighbor_hosts"]
_macsec_service_ready = NAMESPACE["_macsec_service_ready"]
_macsec_service_diagnostics = NAMESPACE["_macsec_service_diagnostics"]
_start_csonic_macsec_service = NAMESPACE["_start_csonic_macsec_service"]
_stop_csonic_macsec_service = NAMESPACE["_stop_csonic_macsec_service"]
enable_macsec_feature = NAMESPACE["enable_macsec_feature"]
disable_macsec_feature = NAMESPACE["disable_macsec_feature"]


class ShellHost:
    def __init__(self, responses=None, num_asics=1):
        self.responses = responses or {}
        self.shell_calls = []
        self._num_asics = num_asics
        self.hostname = "host"

    def shell(self, command, **kwargs):
        self.shell_calls.append((command, kwargs))
        response = self.responses.get(command)
        if isinstance(response, list):
            return response.pop(0)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise AssertionError("Unexpected shell command: {}".format(command))
        return response

    def num_asics(self):
        return self._num_asics


class CsonicShellHost(FakeCsonicHost, ShellHost):
    def __init__(self, responses=None, container_name="csonic_vm"):
        ShellHost.__init__(self, responses=responses)
        self.container_name = container_name
        self.vm_host_ip = None
        self.vm_host_user = None


class EosShellHost(FakeEosHost, ShellHost):
    def __init__(self):
        ShellHost.__init__(self)


def _successful_lines(*lines):
    return {"rc": 0, "stdout_lines": list(lines), "stdout": "\n".join(lines)}


def test_converged_csonic_logical_neighbors_are_deduplicated():
    csonic = CsonicShellHost(container_name="csonic_shared")
    eos = EosShellHost()
    neighbors = {
        "ARISTA01T1": {"host": csonic},
        "ARISTA02T1": {"host": CsonicShellHost(container_name="csonic_shared")},
        "ARISTA03T1": {"host": CsonicShellHost(container_name="csonic_shared")},
        "EOS01": {"host": eos},
    }

    unique = _unique_macsec_neighbor_hosts(neighbors)

    assert list(unique) == ["ARISTA01T1", "EOS01"]
    assert unique["ARISTA01T1"]["host"] is csonic
    assert unique["EOS01"]["host"] is eos


def test_csonic_readiness_uses_supervisor_without_nested_docker():
    host = CsonicShellHost({
        "supervisorctl status macsecmgrd": _successful_lines(
            "macsecmgrd RUNNING pid 105, uptime 0:00:07"
        ),
    })

    assert _macsec_service_ready(host, 1)
    assert host.shell_calls == [("supervisorctl status macsecmgrd", {})]
    assert all("docker ps" not in command for command, _ in host.shell_calls)


def test_csonic_readiness_rejects_missing_stopped_and_failed_service():
    missing = CsonicShellHost({
        "supervisorctl status macsecmgrd": {
            "rc": 4,
            "stdout": "macsecmgrd: ERROR (no such process)",
        },
    })
    stopped = CsonicShellHost({
        "supervisorctl status macsecmgrd": _successful_lines("macsecmgrd STOPPED"),
    })
    failed = CsonicShellHost({
        "supervisorctl status macsecmgrd": RuntimeError("transport failed"),
    })

    assert not _macsec_service_ready(missing, 1)
    assert not _macsec_service_ready(stopped, 1)
    assert not _macsec_service_ready(failed, 1)


def test_sonic_host_still_requires_container_and_process():
    host = ShellHost({
        "docker ps | grep macsec | grep -v grep": _successful_lines("macsec"),
        "ps -ef | grep macsecmgrd | grep -v grep": _successful_lines("macsecmgrd"),
    })

    assert _macsec_service_ready(host, 1)
    assert [command for command, _ in host.shell_calls] == [
        "docker ps | grep macsec | grep -v grep",
        "ps -ef | grep macsecmgrd | grep -v grep",
    ]


def test_sonic_host_rejects_missing_container_or_failed_process_command():
    missing_container = ShellHost({
        "docker ps | grep macsec | grep -v grep": _successful_lines(),
    })
    failed_process = ShellHost({
        "docker ps | grep macsec | grep -v grep": _successful_lines("macsec"),
        "ps -ef | grep macsecmgrd | grep -v grep": {"rc": 1, "stdout": ""},
    })

    assert not _macsec_service_ready(missing_container, 1)
    assert not _macsec_service_ready(failed_process, 1)


def test_enable_excludes_eos_neighbor_from_readiness_checks():
    duthost = ShellHost({
        "docker ps | grep macsec | grep -v grep": _successful_lines("macsec"),
        "ps -ef | grep macsecmgrd | grep -v grep": _successful_lines("macsecmgrd"),
    })
    eos = EosShellHost()
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["wait_until"] = MagicMock(side_effect=lambda _timeout, _interval, _delay, check: check())

    enable_macsec_feature(duthost, {"eos": {"host": eos}})

    assert eos.shell_calls == []
    NAMESPACE["global_cmd"].assert_called_once_with(
        duthost, {"eos": {"host": eos}}, "sudo config feature state macsec enabled"
    )


def test_enable_preserves_dut_multi_asic_instance_counting():
    duthost = ShellHost({
        "docker ps | grep macsec | grep -v grep": _successful_lines("macsec0", "macsec1"),
        "ps -ef | grep macsecmgrd | grep -v grep": _successful_lines("mgr0", "mgr1"),
    }, num_asics=2)
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["wait_until"] = MagicMock(side_effect=lambda _timeout, _interval, _delay, check: check())

    enable_macsec_feature(duthost, {})

    assert [command for command, _ in duthost.shell_calls] == [
        "docker ps | grep macsec | grep -v grep",
        "ps -ef | grep macsecmgrd | grep -v grep",
    ]


def test_timeout_diagnostics_distinguish_csonic_from_sonic_runtime():
    csonic = CsonicShellHost()
    csonic.shell = MagicMock(return_value={"rc": 0, "stdout": "RUNNING", "stderr": ""})
    sonic = ShellHost()
    sonic.shell = MagicMock(return_value={"rc": 1, "stdout": "", "stderr": "inactive"})

    csonic_diagnostics = _macsec_service_diagnostics(csonic)
    sonic_diagnostics = _macsec_service_diagnostics(sonic)

    assert csonic_diagnostics["runtime"] == "csonic"
    assert set(csonic_diagnostics["checks"]) == {
        "supervisor", "process", "feature", "database", "supervisor_config", "syslog"
    }
    assert sonic_diagnostics["runtime"] == "sonic"
    assert set(sonic_diagnostics["checks"]) == {"containers", "processes", "feature", "service"}
    assert all(call.kwargs == {"module_ignore_errors": True} for call in csonic.shell.call_args_list)
    assert all(call.kwargs == {"module_ignore_errors": True} for call in sonic.shell.call_args_list)


def test_command_output_shapes_fail_closed():
    assert _command_output_lines({"rc": 0, "stdout_lines": ("one", "two")}) == ["one", "two"]
    assert _command_output_lines({"rc": 0, "stdout": "one\ntwo\n"}) == ["one", "two"]
    assert _command_output_lines({"rc": 1, "stdout_lines": ["stale"]}) == []
    assert _command_output_lines({"stdout_lines": ["missing rc"]}) == []
    assert _command_output_lines(None) == []


def test_ansible_mapping_results_are_supported():
    result = UserDict({
        "rc": 0,
        "stdout": "macsec Up 3 minutes\n",
        "stdout_lines": ["macsec Up 3 minutes"],
        "stderr": "",
    })
    host = ShellHost({
        "docker ps | grep macsec | grep -v grep": result,
        "ps -ef | grep macsecmgrd | grep -v grep": UserDict({
            "rc": 0,
            "stdout": "/usr/bin/macsecmgrd",
        }),
    })

    assert _macsec_service_ready(host, 1)
    assert _command_output_lines(result) == ["macsec Up 3 minutes"]
    assert NAMESPACE["_command_diagnostic"](result) == {
        "rc": 0,
        "stdout": "macsec Up 3 minutes\n",
        "stderr": "",
    }


def test_csonic_service_lifecycle_uses_supervisor_not_docker():
    host = CsonicShellHost()
    host.responses = MagicMock(return_value={"rc": 0, "stdout": ""})

    def shell(command, **kwargs):
        host.shell_calls.append((command, kwargs))
        return {"rc": 0, "stdout": ""}

    host.shell = shell

    assert _start_csonic_macsec_service(host)
    assert _stop_csonic_macsec_service(host)
    assert len(host.shell_calls) == 2
    assert all("supervisorctl" in command for command, _ in host.shell_calls)
    assert all("docker" not in command for command, _ in host.shell_calls)
    assert all(kwargs == {"module_ignore_errors": True} for _, kwargs in host.shell_calls)


def test_enable_operates_on_shared_csonic_container_once():
    duthost = ShellHost({
        "docker ps | grep macsec | grep -v grep": _successful_lines("macsec"),
        "ps -ef | grep macsecmgrd | grep -v grep": _successful_lines("macsecmgrd"),
    })
    csonic = CsonicShellHost({
        "supervisorctl status macsecmgrd": _successful_lines("macsecmgrd RUNNING"),
    }, container_name="csonic_shared")
    duplicate = CsonicShellHost(container_name="csonic_shared")
    neighbors = {
        "ARISTA01T1": {"host": csonic},
        "ARISTA02T1": {"host": duplicate},
    }
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["wait_until"] = MagicMock(side_effect=lambda _timeout, _interval, _delay, check: check())
    NAMESPACE["_start_csonic_macsec_service"] = MagicMock(return_value=True)

    enable_macsec_feature(duthost, neighbors)

    NAMESPACE["global_cmd"].assert_called_once()
    selected = NAMESPACE["global_cmd"].call_args.args[1]
    assert list(selected) == ["ARISTA01T1"]
    NAMESPACE["_start_csonic_macsec_service"].assert_called_once_with(csonic)
    assert duplicate.shell_calls == []


def test_disable_excludes_eos_and_stops_csonic_service():
    eos = EosShellHost()
    csonic = CsonicShellHost()

    def shell(command, **kwargs):
        csonic.shell_calls.append((command, kwargs))
        return {"rc": 0, "stdout": ""}

    csonic.shell = shell
    neighbors = {"eos": {"host": eos}, "csonic": {"host": csonic}}
    duthost = ShellHost()
    NAMESPACE["global_cmd"] = MagicMock()

    disable_macsec_feature(duthost, neighbors)

    assert eos.shell_calls == []
    assert len(csonic.shell_calls) == 1
    assert "supervisorctl stop macsecmgrd" in csonic.shell_calls[0][0]
    NAMESPACE["global_cmd"].assert_called_once_with(
        duthost, neighbors, "sudo config feature state macsec disabled"
    )
