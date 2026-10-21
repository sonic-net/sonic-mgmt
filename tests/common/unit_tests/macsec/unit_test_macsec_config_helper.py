"""Focused unit tests for MACsec service readiness across neighbor runtimes."""

import ast
import shlex
import subprocess
from collections import UserDict
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import MagicMock

import pytest


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
    "_host_is_multi_asic",
    "_host_platform_asic",
    "_run_required_macsec_command",
    "_csonic_config_db_hset",
    "_csonic_config_db_delete",
    "_csonic_config_db_hdel",
    "_wait_for_macsec_tasks",
    "_macsec_host_key",
    "_macsec_endpoint_key",
    "_unique_macsec_neighbor_hosts",
    "_macsec_service_ready",
    "_command_diagnostic",
    "_macsec_service_diagnostics",
    "_macsec_interface_diagnostics",
    "_supervisor_macsec_state",
    "_csonic_macsec_service_state",
    "_start_csonic_macsec_service",
    "_restore_csonic_post_state",
    "_stop_csonic_macsec_service",
    "_rollback_csonic_macsec_service",
    "_macsec_configuration_targets",
    "_rollback_macsec_configuration",
    "set_macsec_profile",
    "delete_macsec_profile",
    "enable_macsec_port",
    "disable_macsec_port",
    "enable_macsec_feature",
    "disable_macsec_feature",
    "setup_macsec_configuration",
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
    "shlex": shlex,
    "logger": MagicMock(),
    "time": MagicMock(),
}
exec(compile(ast.Module(body=NODES, type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)

CSONIC_MACSEC_SUPERVISOR_CONFIG = NAMESPACE["CSONIC_MACSEC_SUPERVISOR_CONFIG"]
_command_output_lines = NAMESPACE["_command_output_lines"]
_host_is_multi_asic = NAMESPACE["_host_is_multi_asic"]
_host_platform_asic = NAMESPACE["_host_platform_asic"]
_run_required_macsec_command = NAMESPACE["_run_required_macsec_command"]
_wait_for_macsec_tasks = NAMESPACE["_wait_for_macsec_tasks"]
_unique_macsec_neighbor_hosts = NAMESPACE["_unique_macsec_neighbor_hosts"]
_macsec_service_ready = NAMESPACE["_macsec_service_ready"]
_macsec_service_diagnostics = NAMESPACE["_macsec_service_diagnostics"]
_macsec_interface_diagnostics = NAMESPACE["_macsec_interface_diagnostics"]
_start_csonic_macsec_service = NAMESPACE["_start_csonic_macsec_service"]
_stop_csonic_macsec_service = NAMESPACE["_stop_csonic_macsec_service"]
_rollback_csonic_macsec_service = NAMESPACE["_rollback_csonic_macsec_service"]
_macsec_configuration_targets = NAMESPACE["_macsec_configuration_targets"]
_rollback_macsec_configuration = NAMESPACE["_rollback_macsec_configuration"]
set_macsec_profile = NAMESPACE["set_macsec_profile"]
delete_macsec_profile = NAMESPACE["delete_macsec_profile"]
enable_macsec_port = NAMESPACE["enable_macsec_port"]
disable_macsec_port = NAMESPACE["disable_macsec_port"]
enable_macsec_feature = NAMESPACE["enable_macsec_feature"]
disable_macsec_feature = NAMESPACE["disable_macsec_feature"]
setup_macsec_configuration = NAMESPACE["setup_macsec_configuration"]


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


def test_csonic_macsec_setup_writes_config_db_without_optional_cli_plugin():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.commands = []

        def command(self, command):
            self.commands.append(command)
            return {"rc": 0, "stdout": "", "stderr": ""}

    host = CsonicCommandHost()

    set_macsec_profile(
        host, "128_SCI", 63, "GCM-AES-128", "cak", "ckn", "security", "true"
    )
    enable_macsec_port(host, "Ethernet1", "128_SCI")

    assert _host_is_multi_asic(host) is False
    assert _host_platform_asic(host) is None
    assert host.commands[0].startswith(
        "sonic-db-cli CONFIG_DB HSET 'MACSEC_PROFILE|128_SCI' ")
    assert "priority 63" in host.commands[0]
    assert "send_sci true" in host.commands[0]
    assert "rekey_period 0" in host.commands[0]
    assert host.commands[1] == (
        "sonic-db-cli CONFIG_DB HSET 'PORT|Ethernet1' macsec 128_SCI")


def test_csonic_macsec_profile_zero_resets_existing_rekey_period():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.commands = []

        def command(self, command):
            self.commands.append(command)
            return {"rc": 0, "stdout": "", "stderr": ""}

    host = CsonicCommandHost()
    set_macsec_profile(
        host, "128_SCI", 63, "GCM-AES-128", "cak", "ckn",
        "security", "true", rekey_period=0)

    assert "rekey_period 0" in host.commands[0]


def test_csonic_macsec_profile_maps_flags_to_config_db_schema():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.commands = []

        def command(self, command):
            self.commands.append(command)
            return {"rc": 0, "stdout": "", "stderr": ""}

    host = CsonicCommandHost()

    set_macsec_profile(
        host, "256_XPN_NO_SCI", 65, "GCM-AES-XPN-256", "cak", "ckn",
        "security", "false", rekey_period=240
    )

    assert "send_sci false" in host.commands[0]
    assert "rekey_period 240" in host.commands[0]
    assert "no_send_sci" not in host.commands[0]


def test_csonic_macsec_cleanup_deletes_config_db_entries_directly():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.commands = []

        def command(self, command, **kwargs):
            self.commands.append((command, kwargs))
            return {"rc": 0, "stdout": "", "stderr": ""}

    host = CsonicCommandHost()

    disable_macsec_port(host, "Ethernet1")
    delete_macsec_profile(host, "128_SCI")

    assert host.commands == [
        ("sonic-db-cli CONFIG_DB HDEL 'PORT|Ethernet1' macsec", {}),
        ("sonic-db-cli CONFIG_DB DEL 'MACSEC_PROFILE|128_SCI'", {}),
    ]


def test_regular_sonic_macsec_setup_preserves_config_cli():
    class SonicCommandHost:
        is_multi_asic = False
        facts = {}

        def __init__(self):
            self.commands = []

        def command(self, command):
            self.commands.append(command)
            return {"rc": 0, "stdout": "", "stderr": ""}

    host = SonicCommandHost()
    NAMESPACE["get_portchannel"] = MagicMock(return_value={})
    NAMESPACE["find_portchannel_from_member"] = MagicMock(return_value=None)
    NAMESPACE["getns_prefix"] = MagicMock(return_value=" ")

    set_macsec_profile(
        host, "128_SCI", 63, "GCM-AES-128", "cak", "ckn", "security", "true"
    )
    enable_macsec_port(host, "Ethernet1", "128_SCI")

    assert host.commands[0].startswith("config macsec profile add 128_SCI ")
    assert host.commands[1].split() == [
        "config", "macsec", "port", "add", "Ethernet1", "128_SCI"
    ]


def test_csonic_required_setup_command_fails_closed():
    class FailedCsonicHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def command(self, command):
            return {"rc": 1, "stdout": "", "stderr": "unsupported"}

    with pytest.raises(AssertionError, match="MACsec command failed on csonic_vm"):
        _run_required_macsec_command(FailedCsonicHost(), "config macsec profile add test")


def test_macsec_worker_failures_are_not_silently_ignored():
    tasks = [MagicMock(exitcode=0), MagicMock(exitcode=1)]
    NAMESPACE["wait_all_complete"] = MagicMock()

    with pytest.raises(AssertionError, match=r"task failures: \[1\]"):
        _wait_for_macsec_tasks(tasks, timeout=180)

    NAMESPACE["wait_all_complete"].assert_called_once_with(timeout=180)


def test_csonic_interface_diagnostics_query_container_directly():
    host = CsonicShellHost()
    host.shell = MagicMock(return_value={"rc": 0, "stdout": "ok", "stderr": ""})

    diagnostics = _macsec_interface_diagnostics(host, "Ethernet1")

    assert diagnostics["runtime"] == "csonic"
    assert diagnostics["interface"] == "Ethernet1"
    commands = [call.args[0] for call in host.shell.call_args_list]
    assert 'sonic-db-cli STATE_DB HGET "MACSEC_PORT_TABLE|Ethernet1" state' in commands
    assert 'sonic-db-cli STATE_DB HGET "FIPS_MACSEC_POST_TABLE|sai" post_state' in commands
    assert "test -x /sbin/wpa_supplicant && /sbin/wpa_supplicant -v" in commands
    assert "test -x /sbin/wpa_cli && /sbin/wpa_cli -v" in commands
    assert any("grep -iE 'macsecmgrd|wpa_supplicant|macsec'" in command for command in commands)
    assert "ip -j macsec show" in commands
    assert all("docker exec" not in command for command in commands)


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


def test_shared_csonic_configuration_targets_are_deduplicated():
    csonic = CsonicShellHost(container_name="csonic_shared")
    duplicate = CsonicShellHost(container_name="csonic_shared")
    duthost = ShellHost()
    links = {
        "Ethernet0": {"host": csonic, "port": "Ethernet1"},
        "Ethernet4": {"host": duplicate, "port": "Ethernet1"},
    }

    profile_hosts, endpoints = _macsec_configuration_targets(duthost, links)

    assert profile_hosts == [csonic]
    assert endpoints == [
        (duthost, "Ethernet0"),
        (duthost, "Ethernet4"),
        (csonic, "Ethernet1"),
    ]


def test_setup_configures_shared_csonic_profile_and_endpoint_once():
    duthost = ShellHost()
    csonic = CsonicShellHost(container_name="csonic_shared")
    duplicate = CsonicShellHost(container_name="csonic_shared")
    links = {
        "Ethernet0": {"host": csonic, "port": "Ethernet1"},
        "Ethernet4": {"host": duplicate, "port": "Ethernet1"},
    }
    submit = MagicMock(side_effect=lambda *_args, **_kwargs: MagicMock(exitcode=0))
    NAMESPACE["submit_async_task"] = submit
    NAMESPACE["_wait_for_macsec_tasks"] = MagicMock()
    NAMESPACE["wait_until"] = MagicMock(return_value=True)

    setup_macsec_configuration(
        duthost, links, "128_SCI", 64, "GCM-AES-128", "cak", "ckn",
        "security", "true", 0, {})

    profile_calls = [
        call for call in submit.call_args_list
        if call.args[0] is set_macsec_profile
    ]
    port_calls = [
        call for call in submit.call_args_list
        if call.args[0] is enable_macsec_port
    ]
    assert len(profile_calls) == 2
    assert profile_calls[0].args[1][0] is duthost
    assert profile_calls[1].args[1][0] is csonic
    assert [call.args[1][:2] for call in port_calls] == [
        (duthost, "Ethernet0"),
        (duthost, "Ethernet4"),
        (csonic, "Ethernet1"),
    ]


def test_configuration_rollback_continues_after_individual_failures():
    first = CsonicShellHost(container_name="first")
    second = CsonicShellHost(container_name="second")
    NAMESPACE["disable_macsec_port"] = MagicMock(
        side_effect=[RuntimeError("port failed"), None])
    NAMESPACE["delete_macsec_profile"] = MagicMock(
        side_effect=[RuntimeError("profile failed"), None])

    _rollback_macsec_configuration(
        [first, second], [(first, "Ethernet1"), (second, "Ethernet2")],
        "128_SCI")

    assert NAMESPACE["disable_macsec_port"].call_count == 2
    assert NAMESPACE["delete_macsec_profile"].call_count == 2


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
        "supervisor", "process", "post_state", "feature", "database", "supervisor_config", "syslog"
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


def test_csonic_service_lifecycle_provisions_with_long_timeout():
    host = CsonicShellHost()
    initial = {"state": "MISSING", "config_exists": False, "post_state": None}

    def shell(command, **kwargs):
        host.shell_calls.append((command, kwargs))
        if command == "supervisorctl status macsecmgrd":
            return {"rc": 4, "stdout": "macsecmgrd: ERROR (no such process)", "stderr": ""}
        if command.startswith("test -e "):
            return {"rc": 1, "stdout": "", "stderr": ""}
        if " HGET " in command:
            return {"rc": 0, "stdout": "disabled", "stderr": ""}
        return {"rc": 0, "stdout": "", "stderr": ""}

    host.shell = shell

    assert _start_csonic_macsec_service(host, initial)
    provision = host.shell_calls[0]
    assert "apt-get install -y --no-install-recommends wpasupplicant" in provision[0]
    assert provision[1] == {"module_ignore_errors": True, "timeout": 300}
    assert any('HSET "FIPS_MACSEC_POST_TABLE|sai" post_state disabled' in command
               for command, _ in host.shell_calls)
    assert "cat >" in host.shell_calls[-1][0]
    for command, _ in host.shell_calls:
        if "\n" in command:
            subprocess.run(
                ["bash", "-n"], input=command, text=True, check=True)
    assert host._sonic_mgmt_macsec_initial == initial


def test_csonic_start_accepts_supervisor_transitional_states():
    for supervisor_state in ("STARTING", "BACKOFF"):
        host = CsonicShellHost()
        initial = {
            "state": supervisor_state,
            "config_exists": True,
            "post_state": "disabled",
        }

        def shell(command, **kwargs):
            host.shell_calls.append((command, kwargs))
            if command == "supervisorctl status macsecmgrd":
                return {"rc": 3, "stdout": "macsecmgrd {}".format(supervisor_state), "stderr": ""}
            if command.startswith("test -e "):
                return {"rc": 0, "stdout": "", "stderr": ""}
            if " HGET " in command:
                return {"rc": 0, "stdout": "disabled", "stderr": ""}
            return {"rc": 0, "stdout": "", "stderr": ""}

        host.shell = shell
        assert _start_csonic_macsec_service(host, initial)
        assert all(command != "supervisorctl start macsecmgrd"
                   for command, _ in host.shell_calls)


def test_csonic_stop_restores_only_fixture_owned_state():
    for supervisor_state in ("RUNNING", "STARTING", "BACKOFF"):
        host = CsonicShellHost()
        host._sonic_mgmt_macsec_initial = {
            "state": "MISSING",
            "config_exists": False,
            "post_state": None,
        }

        def shell(command, **kwargs):
            host.shell_calls.append((command, kwargs))
            if command == "supervisorctl status macsecmgrd":
                return {"rc": 0, "stdout": "macsecmgrd {}".format(supervisor_state), "stderr": ""}
            if command.startswith("test -e "):
                return {"rc": 0, "stdout": "", "stderr": ""}
            if " HGET " in command:
                return {"rc": 0, "stdout": "disabled", "stderr": ""}
            return {"rc": 0, "stdout": "", "stderr": ""}

        host.shell = shell
        assert _stop_csonic_macsec_service(host)
        assert any(command == "supervisorctl stop macsecmgrd"
                   for command, _ in host.shell_calls)
        assert any("rm -f" in command for command, _ in host.shell_calls)
        assert any(" HDEL " in command for command, _ in host.shell_calls)
        assert not hasattr(host, "_sonic_mgmt_macsec_initial")


def test_csonic_stop_preserves_preexisting_running_daemon_and_post_state():
    host = CsonicShellHost()
    initial = {
        "state": "RUNNING",
        "config_exists": True,
        "post_state": "pass",
    }
    host._sonic_mgmt_macsec_initial = initial

    def shell(command, **kwargs):
        host.shell_calls.append((command, kwargs))
        if command == "supervisorctl status macsecmgrd":
            return {"rc": 0, "stdout": "macsecmgrd RUNNING", "stderr": ""}
        if command.startswith("test -e "):
            return {"rc": 0, "stdout": "", "stderr": ""}
        if " HGET " in command:
            return {"rc": 0, "stdout": "pass", "stderr": ""}
        return {"rc": 0, "stdout": "", "stderr": ""}

    host.shell = shell
    assert _stop_csonic_macsec_service(host)
    commands = [command for command, _ in host.shell_calls]
    assert "supervisorctl stop macsecmgrd" not in commands
    assert not any("rm -f" in command for command in commands)
    assert not any(" HSET " in command or " HDEL " in command
                   for command in commands)


def test_csonic_rollback_rejects_unknown_supervisor_errors():
    host = CsonicShellHost({
        "supervisorctl status macsecmgrd": {
            "rc": 1, "stdout": "", "stderr": "transport failure"},
        "test -e {}".format(CSONIC_MACSEC_SUPERVISOR_CONFIG): {
            "rc": 1, "stdout": "", "stderr": ""},
        'sonic-db-cli STATE_DB HGET "FIPS_MACSEC_POST_TABLE|sai" post_state': {
            "rc": 0, "stdout": "", "stderr": ""},
    })
    initial = {"state": "MISSING", "config_exists": False, "post_state": None}
    assert not _rollback_csonic_macsec_service(host, initial)


def test_csonic_rollback_stops_removes_and_restores_new_resources():
    host = CsonicShellHost()

    def shell(command, **kwargs):
        host.shell_calls.append((command, kwargs))
        if command == "supervisorctl status macsecmgrd":
            return {"rc": 0, "stdout": "macsecmgrd RUNNING", "stderr": ""}
        if command.startswith("test -e "):
            return {"rc": 0, "stdout": "", "stderr": ""}
        if " HGET " in command:
            return {"rc": 0, "stdout": "disabled", "stderr": ""}
        return {"rc": 0, "stdout": "", "stderr": ""}

    host.shell = shell
    initial = {"state": "MISSING", "config_exists": False, "post_state": None}
    assert _rollback_csonic_macsec_service(host, initial)
    commands = [command for command, _ in host.shell_calls]
    assert "supervisorctl stop macsecmgrd" in commands
    assert any("rm -f" in command for command in commands)
    assert any(" HDEL " in command for command in commands)


def test_enable_rolls_back_csonic_initialization_on_readiness_failure():
    duthost = ShellHost()
    csonic = CsonicShellHost()
    initial = {"state": "MISSING", "config_exists": False, "post_state": None}
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["_csonic_macsec_service_state"] = MagicMock(return_value=initial)
    NAMESPACE["_start_csonic_macsec_service"] = MagicMock(return_value=True)
    NAMESPACE["_macsec_service_diagnostics"] = MagicMock(return_value={})
    NAMESPACE["wait_until"] = MagicMock(return_value=False)
    NAMESPACE["_rollback_csonic_macsec_service"] = MagicMock(return_value=True)

    with pytest.raises(AssertionError, match="MACsec readiness timed out"):
        enable_macsec_feature(duthost, {"csonic": {"host": csonic}})

    NAMESPACE["_rollback_csonic_macsec_service"].assert_called_once_with(
        csonic, initial)


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
    initial = {"state": "MISSING", "config_exists": False, "post_state": None}
    NAMESPACE["_csonic_macsec_service_state"] = MagicMock(
        return_value=initial)
    NAMESPACE["_start_csonic_macsec_service"] = MagicMock(return_value=True)
    NAMESPACE["_rollback_csonic_macsec_service"] = MagicMock(return_value=True)

    enable_macsec_feature(duthost, neighbors)

    NAMESPACE["global_cmd"].assert_called_once()
    selected = NAMESPACE["global_cmd"].call_args.args[1]
    assert list(selected) == ["ARISTA01T1"]
    NAMESPACE["_start_csonic_macsec_service"].assert_called_once_with(
        csonic, initial)
    assert duplicate.shell_calls == []


def test_disable_excludes_eos_and_stops_csonic_service():
    eos = EosShellHost()
    csonic = CsonicShellHost()
    neighbors = {"eos": {"host": eos}, "csonic": {"host": csonic}}
    duthost = ShellHost()
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["_stop_csonic_macsec_service"] = MagicMock(return_value=True)

    disable_macsec_feature(duthost, neighbors)

    assert eos.shell_calls == []
    NAMESPACE["_stop_csonic_macsec_service"].assert_called_once_with(csonic)
    NAMESPACE["global_cmd"].assert_called_once_with(
        duthost, neighbors, "sudo config feature state macsec disabled"
    )
