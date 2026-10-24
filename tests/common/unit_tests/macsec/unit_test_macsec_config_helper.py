"""Focused unit tests for MACsec service readiness across neighbor runtimes."""

import ast
import json
import shlex
import subprocess
from collections import UserDict
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import MagicMock, call

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
    "_runtime_port_name",
    "_run_required_macsec_command",
    "_csonic_config_db_hset",
    "_csonic_config_db_delete",
    "_csonic_config_db_hdel",
    "_command_stdout",
    "_macsec_port_profile",
    "_eos_macsec_profile_lines",
    "_decode_macsec_profile_fields",
    "_macsec_profile_snapshot",
    "_macsec_profile_exists",
    "_macsec_profile_fields",
    "_macsec_profile_matches",
    "_restore_macsec_profile",
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
    "_macsec_session_cleanup_hosts",
    "_prepare_macsec_lldp",
    "set_macsec_profile",
    "delete_macsec_profile",
    "enable_macsec_port",
    "disable_macsec_port",
    "_macsec_feature_state",
    "_restore_macsec_feature_state",
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
    "ast": ast,
    "json": json,
    "Mapping": Mapping,
    "shlex": shlex,
    "logger": MagicMock(),
    "time": MagicMock(),
}
exec(compile(ast.Module(body=NODES, type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)
ORIGINAL_NAMESPACE = NAMESPACE.copy()


@pytest.fixture(autouse=True)
def restore_extracted_namespace():
    """Keep per-test mocks from leaking through extracted function globals."""
    NAMESPACE["_macsec_feature_state"] = MagicMock(return_value="disabled")
    NAMESPACE["_restore_macsec_feature_state"] = MagicMock()
    yield
    NAMESPACE.clear()
    NAMESPACE.update(ORIGINAL_NAMESPACE)


CSONIC_MACSEC_SUPERVISOR_CONFIG = NAMESPACE["CSONIC_MACSEC_SUPERVISOR_CONFIG"]
_command_output_lines = NAMESPACE["_command_output_lines"]
_host_is_multi_asic = NAMESPACE["_host_is_multi_asic"]
_host_platform_asic = NAMESPACE["_host_platform_asic"]
_run_required_macsec_command = NAMESPACE["_run_required_macsec_command"]
_command_stdout = NAMESPACE["_command_stdout"]
_macsec_port_profile = NAMESPACE["_macsec_port_profile"]
_decode_macsec_profile_fields = NAMESPACE["_decode_macsec_profile_fields"]
_macsec_profile_snapshot = NAMESPACE["_macsec_profile_snapshot"]
_macsec_profile_exists = NAMESPACE["_macsec_profile_exists"]
_macsec_profile_fields = NAMESPACE["_macsec_profile_fields"]
_macsec_profile_matches = NAMESPACE["_macsec_profile_matches"]
_restore_macsec_profile = NAMESPACE["_restore_macsec_profile"]
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
_macsec_session_cleanup_hosts = NAMESPACE["_macsec_session_cleanup_hosts"]
_prepare_macsec_lldp = NAMESPACE["_prepare_macsec_lldp"]
set_macsec_profile = NAMESPACE["set_macsec_profile"]
delete_macsec_profile = NAMESPACE["delete_macsec_profile"]
enable_macsec_port = NAMESPACE["enable_macsec_port"]
disable_macsec_port = NAMESPACE["disable_macsec_port"]
_macsec_feature_state = NAMESPACE["_macsec_feature_state"]
_restore_macsec_feature_state = NAMESPACE["_restore_macsec_feature_state"]
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


def test_csonic_state_snapshots_are_required_and_preserve_bindings():
    host = CsonicShellHost()
    host.command = MagicMock(side_effect=[
        {"rc": 0, "stdout": "128_SCI\n"},
        {"rc": 0, "stdout": '{"priority": "64"}'},
        {"rc": 1, "stdout": "", "stderr": "redis unavailable"},
    ])
    NAMESPACE["getns_prefix"] = MagicMock(return_value="")

    assert _macsec_port_profile(host, "Ethernet1") == "128_SCI"
    assert _macsec_profile_exists(host, "128_SCI") is True
    with pytest.raises(AssertionError, match="MACsec state query failed"):
        _command_stdout(host, "failing query")


def test_eos_profile_existence_matches_complete_declaration():
    host = EosShellHost()
    host.eos_command = MagicMock(side_effect=[
        {"stdout": ["mac security\n   profile 128_SCI_NEW\n      cipher aes128-gcm"]},
        {"stdout": [["mac security", "   profile 128_SCI", "      cipher aes128-gcm"]]},
    ])

    assert _macsec_profile_exists(host, "128_SCI") is False
    assert _macsec_profile_exists(host, "128_SCI") is True
    assert host.eos_command.call_args_list == [
        call(commands=["show running-config section mac security"]),
        call(commands=["show running-config section mac security"]),
    ]


def test_eos_profile_snapshot_restores_original_lines_exactly():
    host = EosShellHost()
    host.eos_command = MagicMock(return_value={
        "stdout": [[
            "mac security",
            "   profile 128_SCI",
            "      cipher aes128-gcm",
            "      mka key-server priority 64",
            "   profile 128_SCI_NEW",
        ]],
    })
    host.eos_config = MagicMock()

    snapshot = _macsec_profile_snapshot(host, "128_SCI")
    _restore_macsec_profile(host, "128_SCI", snapshot)

    assert snapshot == {
        "runtime": "eos",
        "lines": ["cipher aes128-gcm", "mka key-server priority 64"],
    }
    assert host.eos_config.call_args_list == [
        call(lines=["no profile 128_SCI"], parents=["mac security"]),
        call(
            lines=["cipher aes128-gcm", "mka key-server priority 64"],
            parents=["mac security", "profile 128_SCI"],
        ),
    ]


def test_csonic_profile_snapshot_restores_original_fields_exactly():
    host = CsonicShellHost()
    host.command = MagicMock(side_effect=[
        {"rc": 0, "stdout": '{"priority": "64", "policy": "security"}'},
        {"rc": 0, "stdout": "1"},
        {"rc": 0, "stdout": "2"},
    ])

    snapshot = _macsec_profile_snapshot(host, "128_SCI")
    _restore_macsec_profile(host, "128_SCI", snapshot)

    assert snapshot == {
        "runtime": "sonic",
        "entries": [{
            "namespace": None,
            "fields": {"priority": "64", "policy": "security"},
        }],
    }
    commands = [item.args[0] for item in host.command.call_args_list]
    assert commands[0] == (
        "sonic-db-cli CONFIG_DB HGETALL 'MACSEC_PROFILE|128_SCI'")
    assert commands[1] == (
        "sonic-db-cli CONFIG_DB DEL 'MACSEC_PROFILE|128_SCI'")
    assert commands[2] == (
        "sonic-db-cli CONFIG_DB HSET 'MACSEC_PROFILE|128_SCI' "
        "priority 64 policy security")


def test_multi_asic_profile_snapshot_preserves_each_namespace():
    host = ShellHost()
    host.is_multi_asic = True
    host.get_asic_namespace_list = MagicMock(return_value=["asic0", "asic1"])
    host.command = MagicMock(side_effect=[
        {"rc": 0, "stdout": '{"priority": "64"}'},
        {"rc": 0, "stdout": "{}"},
        {"rc": 0, "stdout": "1"},
        {"rc": 0, "stdout": "2"},
        {"rc": 0, "stdout": "1"},
    ])

    snapshot = _macsec_profile_snapshot(host, "128_SCI")
    _restore_macsec_profile(host, "128_SCI", snapshot)

    assert snapshot["entries"] == [
        {"namespace": "asic0", "fields": {"priority": "64"}},
        {"namespace": "asic1", "fields": None},
    ]
    commands = [item.args[0] for item in host.command.call_args_list]
    assert commands[2:] == [
        "sonic-db-cli -n asic0 CONFIG_DB DEL 'MACSEC_PROFILE|128_SCI'",
        "sonic-db-cli -n asic0 CONFIG_DB HSET 'MACSEC_PROFILE|128_SCI' priority 64",
        "sonic-db-cli -n asic1 CONFIG_DB DEL 'MACSEC_PROFILE|128_SCI'",
    ]


@pytest.mark.parametrize("output", ["[]", "not-json", "priority\n"])
def test_csonic_profile_snapshot_rejects_malformed_output(output):
    host = CsonicShellHost()
    host.command = MagicMock(return_value={"rc": 0, "stdout": output})

    with pytest.raises(AssertionError, match="Malformed MACsec profile snapshot"):
        _macsec_profile_snapshot(host, "128_SCI")


def test_profile_snapshot_accepts_legacy_field_value_lines_and_empty_output():
    host = CsonicShellHost()
    host.command = MagicMock(side_effect=[
        {"rc": 0, "stdout": "priority\n64\npolicy\nsecurity\n"},
        {"rc": 0, "stdout": ""},
    ])

    populated = _macsec_profile_snapshot(host, "128_SCI")
    absent = _macsec_profile_snapshot(host, "MISSING")

    assert populated["entries"][0]["fields"] == {
        "priority": "64", "policy": "security"}
    assert absent["entries"][0]["fields"] is None


def test_sonic_profile_match_requires_requested_fields_in_every_namespace():
    fields = _macsec_profile_fields(
        64, "GCM-AES-128", "cak", "ckn", "security", "true", 0)
    snapshot = {
        "runtime": "sonic",
        "entries": [
            {"namespace": "asic0", "fields": dict(fields)},
            {"namespace": "asic1", "fields": dict(
                fields, enable_replay_protect="false")},
        ],
    }

    assert _macsec_profile_matches(
        snapshot, 64, "GCM-AES-128", "cak", "ckn", "security", "true", 0)

    snapshot["entries"][1]["fields"]["priority"] = "63"
    assert not _macsec_profile_matches(
        snapshot, 64, "GCM-AES-128", "cak", "ckn", "security", "true", 0)


def test_sonic_profile_match_accepts_omitted_zero_rekey_period():
    fields = _macsec_profile_fields(
        64, "GCM-AES-128", "cak", "ckn", "security", "true", 0)
    fields.pop("rekey_period")
    snapshot = {
        "runtime": "sonic",
        "entries": [{"namespace": None, "fields": fields}],
    }

    assert _macsec_profile_matches(
        snapshot, 64, "GCM-AES-128", "cak", "ckn", "security", "true", 0)
    assert not _macsec_profile_matches(
        snapshot, 64, "GCM-AES-128", "cak", "ckn", "security", "true", 240)

    fields.pop("primary_cak")
    assert not _macsec_profile_matches(
        snapshot, 64, "GCM-AES-128", "cak", "ckn", "security", "true", 0)


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


def test_csonic_macsec_port_switches_ovs_data_path_after_config_db():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.events = []

        def command(self, command):
            self.events.append(("command", command))
            return {"rc": 0, "stdout": "", "stderr": ""}

        def set_ovs_macsec_member(self, port, enabled):
            self.events.append(("ovs", port, enabled))

    host = CsonicCommandHost()
    enable_macsec_port(host, "Ethernet1", "128_SCI")

    assert host.events == [
        ("command", 'sonic-db-cli CONFIG_DB HGET "PORT|Ethernet1" macsec'),
        ("command", "sonic-db-cli CONFIG_DB HSET 'PORT|Ethernet1' macsec 128_SCI"),
        ("ovs", "Ethernet1", True),
    ]


def test_csonic_macsec_port_maps_logical_interface_for_config_and_ovs():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.events = []

        def _interface_name(self, port):
            return {
                "Ethernet1": "Ethernet2",
                "Ethernet2": "Ethernet3",
            }.get(port, port)

        def command(self, command):
            self.events.append(("command", command))
            return {"rc": 0, "stdout": "", "stderr": ""}

        def set_ovs_macsec_member(self, port, enabled):
            # Match the real API: it accepts the logical port and resolves it
            # internally. An already translated argument would become
            # Ethernet3 with this intentionally overlapping map.
            self.events.append(("ovs", self._interface_name(port), enabled))

    host = CsonicCommandHost()
    enable_macsec_port(host, "Ethernet1", "128_SCI")

    assert host.events == [
        ("command", 'sonic-db-cli CONFIG_DB HGET "PORT|Ethernet2" macsec'),
        ("command", "sonic-db-cli CONFIG_DB HSET 'PORT|Ethernet2' macsec 128_SCI"),
        ("ovs", "Ethernet2", True),
    ]


def test_csonic_macsec_port_disable_maps_logical_interface_once():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.events = []

        def _interface_name(self, port):
            return {
                "Ethernet1": "Ethernet2",
                "Ethernet2": "Ethernet3",
            }.get(port, port)

        def command(self, command):
            self.events.append(("command", command))
            return {"rc": 0, "stdout": "", "stderr": ""}

        def set_ovs_macsec_member(self, port, enabled):
            self.events.append(("ovs", self._interface_name(port), enabled))

    host = CsonicCommandHost()
    disable_macsec_port(host, "Ethernet1")

    assert host.events == [
        ("ovs", "Ethernet2", False),
        ("command", "sonic-db-cli CONFIG_DB HDEL 'PORT|Ethernet2' macsec"),
    ]


def test_csonic_macsec_port_rolls_back_config_when_ovs_swap_fails():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.events = []

        def command(self, command):
            self.events.append(("command", command))
            stdout = "OLD" if " HGET " in command else ""
            return {"rc": 0, "stdout": stdout, "stderr": ""}

        def set_ovs_macsec_member(self, port, enabled):
            self.events.append(("ovs", port, enabled))
            if enabled and len([event for event in self.events
                                if event == ("ovs", port, enabled)]) == 1:
                raise RuntimeError("swap failed")

    host = CsonicCommandHost()
    with pytest.raises(RuntimeError, match="swap failed"):
        enable_macsec_port(host, "Ethernet1", "NEW")

    assert host.events[-2:] == [
        ("ovs", "Ethernet1", True),
        ("command", "sonic-db-cli CONFIG_DB HSET 'PORT|Ethernet1' macsec OLD"),
    ]


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


def test_csonic_macsec_port_restores_plain_ovs_path_before_config_db_delete():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.events = []

        def command(self, command, **kwargs):
            self.events.append(("command", command))
            return {"rc": 0, "stdout": "", "stderr": ""}

        def set_ovs_macsec_member(self, port, enabled):
            self.events.append(("ovs", port, enabled))

    host = CsonicCommandHost()
    disable_macsec_port(host, "Ethernet1")

    assert host.events == [
        ("ovs", "Ethernet1", False),
        ("command", "sonic-db-cli CONFIG_DB HDEL 'PORT|Ethernet1' macsec"),
    ]


def test_csonic_macsec_port_restores_ovs_path_when_config_delete_fails():
    class CsonicCommandHost(FakeCsonicHost):
        hostname = "csonic_vm"

        def __init__(self):
            self.events = []

        def command(self, command, **kwargs):
            self.events.append(("command", command))
            return {"rc": 1, "stdout": "", "stderr": "delete failed"}

        def set_ovs_macsec_member(self, port, enabled):
            self.events.append(("ovs", port, enabled))

    host = CsonicCommandHost()
    with pytest.raises(AssertionError, match="MACsec command failed"):
        disable_macsec_port(host, "Ethernet1")

    assert host.events == [
        ("ovs", "Ethernet1", False),
        ("command", "sonic-db-cli CONFIG_DB HDEL 'PORT|Ethernet1' macsec"),
        ("ovs", "Ethernet1", True),
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
    NAMESPACE["_macsec_profile_snapshot"] = MagicMock(
        return_value={"runtime": "sonic", "entries": []})
    NAMESPACE["_macsec_port_profile"] = MagicMock(return_value=None)
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


def test_setup_reuses_matching_profiles_before_rebinding_ports():
    duthost = ShellHost()
    neighbor = CsonicShellHost()
    links = {"Ethernet0": {"host": neighbor, "port": "Ethernet1"}}
    submit = MagicMock(side_effect=lambda *_args, **_kwargs: MagicMock(exitcode=0))
    NAMESPACE["submit_async_task"] = submit
    NAMESPACE["_wait_for_macsec_tasks"] = MagicMock()
    NAMESPACE["_macsec_profile_snapshot"] = MagicMock(side_effect=[
        {
            "runtime": "sonic",
            "entries": [{
                "namespace": None,
                "fields": _macsec_profile_fields(
                    64, "GCM-AES-128", "cak", "ckn", "security", "true", 0),
            }],
        },
        {
            "runtime": "sonic",
            "entries": [{
                "namespace": None,
                "fields": _macsec_profile_fields(
                    63, "GCM-AES-128", "cak", "ckn", "security", "true", 0),
            }],
        },
    ])
    NAMESPACE["_macsec_port_profile"] = MagicMock(return_value="128_SCI_NEW")
    NAMESPACE["wait_until"] = MagicMock(return_value=True)

    setup_macsec_configuration(
        duthost, links, "128_SCI", 64, "GCM-AES-128", "cak", "ckn",
        "security", "true", 0, {})

    assert not [
        item for item in submit.call_args_list
        if item.args[0] is set_macsec_profile
    ]
    assert [
        item.args[1][:2] for item in submit.call_args_list
        if item.args[0] is enable_macsec_port
    ] == [
        (duthost, "Ethernet0"),
        (neighbor, "Ethernet1"),
    ]


def test_matching_profile_still_applies_lldp_workaround():
    duthost = ShellHost()
    neighbor = CsonicShellHost()
    links = {"Ethernet0": {"host": neighbor, "port": "Ethernet1"}}
    fields64 = _macsec_profile_fields(
        64, "GCM-AES-128", "cak", "ckn", "security", "false", 0)
    fields63 = dict(fields64, priority="63")
    NAMESPACE["_macsec_profile_snapshot"] = MagicMock(side_effect=[
        {"runtime": "sonic", "entries": [{"namespace": None, "fields": fields64}]},
        {"runtime": "sonic", "entries": [{"namespace": None, "fields": fields63}]},
    ])
    NAMESPACE["_macsec_port_profile"] = MagicMock(return_value=None)
    submit = MagicMock(
        side_effect=lambda *_args, **_kwargs: MagicMock(exitcode=0))
    NAMESPACE["submit_async_task"] = submit
    NAMESPACE["_wait_for_macsec_tasks"] = MagicMock()
    NAMESPACE["wait_until"] = MagicMock(return_value=True)
    NAMESPACE["_prepare_macsec_lldp"] = MagicMock()

    setup_macsec_configuration(
        duthost, links, "128", 64, "GCM-AES-128", "cak", "ckn",
        "security", "false", 0, {})

    assert [item.args for item in submit.call_args_list
            if item.args[0] is NAMESPACE["_prepare_macsec_lldp"]] == [
        (NAMESPACE["_prepare_macsec_lldp"], (duthost, "false")),
        (NAMESPACE["_prepare_macsec_lldp"], (neighbor, "false")),
    ]


def test_matching_profile_lldp_failure_waits_for_profile_workers():
    duthost = ShellHost()
    neighbor = CsonicShellHost()
    links = {"Ethernet0": {"host": neighbor, "port": "Ethernet1"}}
    changed = {"runtime": "sonic", "entries": []}
    matching = {
        "runtime": "sonic",
        "entries": [{
            "namespace": None,
            "fields": _macsec_profile_fields(
                63, "GCM-AES-128", "cak", "ckn", "security", "false", 0),
        }],
    }
    NAMESPACE["_macsec_profile_snapshot"] = MagicMock(
        side_effect=[changed, matching])
    NAMESPACE["_macsec_port_profile"] = MagicMock(return_value=None)
    submitted = []

    def submit(target, args):
        task = MagicMock(exitcode=0, target=target)
        submitted.append((target, args, task))
        return task

    def wait_for_tasks(tasks, timeout):
        assert timeout == 180
        assert tasks == [submitted[0][2], submitted[1][2]]
        assert submitted[0][:2] == (
            set_macsec_profile,
            (duthost, "128", 64, "GCM-AES-128", "cak", "ckn",
             "security", "false", 0))
        assert submitted[1][:2] == (
            NAMESPACE["_prepare_macsec_lldp"], (neighbor, "false"))
        raise AssertionError("LLDP preparation failed")

    NAMESPACE["submit_async_task"] = submit
    NAMESPACE["_wait_for_macsec_tasks"] = wait_for_tasks
    NAMESPACE["_rollback_macsec_configuration"] = MagicMock()

    with pytest.raises(AssertionError, match="LLDP preparation failed"):
        setup_macsec_configuration(
            duthost, links, "128", 64, "GCM-AES-128", "cak", "ckn",
            "security", "false", 0, {})

    NAMESPACE["_rollback_macsec_configuration"].assert_called_once_with(
        [(duthost, changed)], [], "128")


def test_session_cleanup_skips_physical_dut_but_keeps_vs_dut():
    physical = ShellHost()
    physical.facts = {"asic_type": "mellanox"}
    virtual = ShellHost()
    virtual.facts = {"asic_type": "vs"}
    neighbor = CsonicShellHost()

    assert _macsec_session_cleanup_hosts(physical, [neighbor]) == [neighbor]
    assert _macsec_session_cleanup_hosts(virtual, [neighbor]) == [
        virtual, neighbor]


def test_profile_failure_does_not_touch_existing_port_bindings():
    duthost = ShellHost()
    neighbor = CsonicShellHost()
    links = {"Ethernet0": {"host": neighbor, "port": "Ethernet1"}}
    NAMESPACE["_macsec_profile_snapshot"] = MagicMock(
        return_value={"runtime": "sonic", "entries": []})
    NAMESPACE["_macsec_port_profile"] = MagicMock(return_value="128_SCI")
    NAMESPACE["submit_async_task"] = MagicMock(
        return_value=MagicMock(exitcode=1))
    NAMESPACE["_wait_for_macsec_tasks"] = MagicMock(
        side_effect=AssertionError("profile failed"))
    NAMESPACE["_rollback_macsec_configuration"] = MagicMock()

    with pytest.raises(AssertionError, match="profile failed"):
        setup_macsec_configuration(
            duthost, links, "128_SCI_NEW", 64, "GCM-AES-128", "cak",
            "ckn", "security", "true", 0, {})

    rollback = NAMESPACE["_rollback_macsec_configuration"]
    assert rollback.call_count == 1
    assert rollback.call_args.args[1] == []


def test_profile_failure_restores_only_profiles_attempted_by_setup():
    duthost = ShellHost()
    neighbor = CsonicShellHost()
    links = {"Ethernet0": {"host": neighbor, "port": "Ethernet1"}}
    matching = {
        "runtime": "sonic",
        "entries": [{
            "namespace": None,
            "fields": _macsec_profile_fields(
                64, "GCM-AES-128", "cak", "ckn", "security", "true", 0),
        }],
    }
    changed = {"runtime": "sonic", "entries": []}
    NAMESPACE["_macsec_profile_snapshot"] = MagicMock(
        side_effect=[matching, changed])
    NAMESPACE["_macsec_port_profile"] = MagicMock(return_value=None)
    NAMESPACE["submit_async_task"] = MagicMock(
        return_value=MagicMock(exitcode=1))
    NAMESPACE["_wait_for_macsec_tasks"] = MagicMock(
        side_effect=AssertionError("neighbor profile failed"))
    NAMESPACE["_rollback_macsec_configuration"] = MagicMock()

    with pytest.raises(AssertionError, match="neighbor profile failed"):
        setup_macsec_configuration(
            duthost, links, "128_SCI", 64, "GCM-AES-128", "cak",
            "ckn", "security", "true", 0, {})

    rollback = NAMESPACE["_rollback_macsec_configuration"]
    rollback.assert_called_once_with(
        [(neighbor, changed)], [], "128_SCI")


def test_configuration_rollback_restores_only_attempted_bindings():
    first = CsonicShellHost(container_name="first")
    second = CsonicShellHost(container_name="second")
    NAMESPACE["disable_macsec_port"] = MagicMock(
        side_effect=RuntimeError("port failed"))
    NAMESPACE["enable_macsec_port"] = MagicMock()
    NAMESPACE["_restore_macsec_profile"] = MagicMock(
        side_effect=[RuntimeError("profile failed"), None])
    first_snapshot = {"runtime": "sonic", "entries": []}
    second_snapshot = {"runtime": "sonic", "entries": []}

    _rollback_macsec_configuration(
        [(first, first_snapshot), (second, second_snapshot)],
        [(first, "Ethernet1", None), (second, "Ethernet2", "128_SCI")],
        "128_SCI_NEW")

    NAMESPACE["disable_macsec_port"].assert_called_once_with(
        first, "Ethernet1")
    NAMESPACE["enable_macsec_port"].assert_called_once_with(
        second, "Ethernet2", "128_SCI")
    assert NAMESPACE["_restore_macsec_profile"].call_count == 2


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


def test_csonic_service_snapshot_aborts_on_post_query_failure():
    host = CsonicShellHost({
        "supervisorctl status macsecmgrd": {
            "rc": 4, "stdout": "macsecmgrd: ERROR (no such process)",
            "stderr": ""},
        "test -e {}".format(CSONIC_MACSEC_SUPERVISOR_CONFIG): {
            "rc": 1, "stdout": "", "stderr": ""},
        'sonic-db-cli STATE_DB HGET "FIPS_MACSEC_POST_TABLE|sai" post_state': {
            "rc": 1, "stdout": "", "stderr": "redis unavailable"},
    })

    with pytest.raises(AssertionError, match="Failed to snapshot cSONiC POST state"):
        NAMESPACE["_csonic_macsec_service_state"](host)


@pytest.mark.parametrize(
    "status,config,expected_error",
    [
        (
            {"rc": 124, "stdout": "", "stderr": "status timed out"},
            {"rc": 1, "stdout": "", "stderr": ""},
            "Failed to snapshot cSONiC Supervisor state",
        ),
        (
            {"rc": 0, "stdout": "macsecmgrd RUNNING", "stderr": ""},
            {"rc": 124, "stdout": "", "stderr": "config query timed out"},
            "Failed to snapshot cSONiC Supervisor config",
        ),
    ],
)
def test_csonic_service_snapshot_rejects_unknown_supervisor_state(
        status, config, expected_error):
    host = CsonicShellHost({
        "supervisorctl status macsecmgrd": status,
        "test -e {}".format(CSONIC_MACSEC_SUPERVISOR_CONFIG): config,
        'sonic-db-cli STATE_DB HGET "FIPS_MACSEC_POST_TABLE|sai" post_state': {
            "rc": 0, "stdout": "pass", "stderr": ""},
    })

    with pytest.raises(AssertionError, match=expected_error):
        NAMESPACE["_csonic_macsec_service_state"](host)


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
    assert "apt-get" not in provision[0]
    assert "macsec_sonic = MACsec Ethernet driver for SONiC" in provision[0]
    assert "/etc/wpa_supplicant.conf" in provision[0]
    assert "ip link add link sm_macsec_base name sm_macsec_test type macsec" in provision[0]
    assert "trap cleanup_macsec_probe EXIT" in provision[0]
    assert provision[1] == {"module_ignore_errors": True, "timeout": 300}
    assert any('HSET "FIPS_MACSEC_POST_TABLE|sai" post_state disabled' in command
               for command, _ in host.shell_calls)
    assert "cat >" in host.shell_calls[-1][0]
    for command, _ in host.shell_calls:
        if "\n" in command:
            subprocess.run(
                ["bash", "-n"], input=command, text=True, check=True)
    assert host._sonic_mgmt_macsec_initial == initial


def test_csonic_start_preserves_first_ownership_snapshot():
    host = CsonicShellHost()
    ownership = {
        "state": "MISSING",
        "config_exists": False,
        "post_state": None,
    }
    attempt = {
        "state": "RUNNING",
        "config_exists": True,
        "post_state": "disabled",
    }
    host._sonic_mgmt_macsec_initial = ownership

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
    assert _start_csonic_macsec_service(host, attempt)
    assert host._sonic_mgmt_macsec_initial is ownership


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


def test_csonic_stop_retains_ownership_token_when_rollback_fails():
    host = CsonicShellHost()
    ownership = {
        "state": "MISSING",
        "config_exists": False,
        "post_state": None,
    }
    host._sonic_mgmt_macsec_initial = ownership
    NAMESPACE["_rollback_csonic_macsec_service"] = MagicMock(
        return_value=False)

    assert not _stop_csonic_macsec_service(host)
    assert host._sonic_mgmt_macsec_initial is ownership


def test_csonic_stop_retains_ownership_token_when_rollback_raises():
    host = CsonicShellHost()
    ownership = {
        "state": "MISSING",
        "config_exists": False,
        "post_state": None,
    }
    host._sonic_mgmt_macsec_initial = ownership
    NAMESPACE["_rollback_csonic_macsec_service"] = MagicMock(
        side_effect=RuntimeError("restore failed"))

    with pytest.raises(RuntimeError, match="restore failed"):
        _stop_csonic_macsec_service(host)
    assert host._sonic_mgmt_macsec_initial is ownership


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


def test_feature_state_snapshot_and_restore_preserve_absence():
    host = CsonicShellHost()
    host.command = MagicMock(side_effect=[
        {"rc": 0, "stdout": "enabled"},
        {"rc": 0, "stdout": ""},
        {"rc": 0, "stdout": "1"},
        {"rc": 0, "stdout": "1"},
    ])

    assert _macsec_feature_state(host) == "enabled"
    assert _macsec_feature_state(host) is None
    _restore_macsec_feature_state(host, "enabled")
    _restore_macsec_feature_state(host, None)

    commands = [item.args[0] for item in host.command.call_args_list]
    assert commands == [
        'sonic-db-cli CONFIG_DB HGET "FEATURE|macsec" state',
        'sonic-db-cli CONFIG_DB HGET "FEATURE|macsec" state',
        "sudo config feature state macsec enabled",
        'sonic-db-cli CONFIG_DB HDEL "FEATURE|macsec" state',
    ]


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
    assert NAMESPACE["_restore_macsec_feature_state"].call_args_list == [
        call(csonic, "disabled"), call(duthost, "disabled")]


def test_failed_reenable_preserves_first_ownership_snapshot():
    duthost = ShellHost()
    csonic = CsonicShellHost()
    ownership = {
        "state": "MISSING",
        "config_exists": False,
        "post_state": None,
    }
    attempt = {
        "state": "RUNNING",
        "config_exists": True,
        "post_state": "disabled",
    }
    csonic._sonic_mgmt_macsec_initial = ownership
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["_csonic_macsec_service_state"] = MagicMock(
        return_value=attempt)
    NAMESPACE["_start_csonic_macsec_service"] = MagicMock(
        return_value=True)
    NAMESPACE["_macsec_service_diagnostics"] = MagicMock(return_value={})
    NAMESPACE["wait_until"] = MagicMock(return_value=False)
    NAMESPACE["_rollback_csonic_macsec_service"] = MagicMock(
        return_value=True)

    with pytest.raises(AssertionError, match="MACsec readiness timed out"):
        enable_macsec_feature(duthost, {"csonic": {"host": csonic}})

    NAMESPACE["_rollback_csonic_macsec_service"].assert_called_once_with(
        csonic, attempt)
    assert csonic._sonic_mgmt_macsec_initial is ownership


def test_failed_first_enable_retains_snapshot_when_rollback_fails():
    duthost = ShellHost()
    csonic = CsonicShellHost()
    initial = {
        "state": "MISSING",
        "config_exists": False,
        "post_state": None,
    }
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["_csonic_macsec_service_state"] = MagicMock(
        return_value=initial)
    NAMESPACE["_start_csonic_macsec_service"] = MagicMock(
        return_value=True)
    NAMESPACE["_macsec_service_diagnostics"] = MagicMock(return_value={})
    NAMESPACE["wait_until"] = MagicMock(return_value=False)
    NAMESPACE["_rollback_csonic_macsec_service"] = MagicMock(
        return_value=False)

    with pytest.raises(AssertionError, match="MACsec readiness timed out"):
        enable_macsec_feature(duthost, {"csonic": {"host": csonic}})

    assert csonic._sonic_mgmt_macsec_initial is initial


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
