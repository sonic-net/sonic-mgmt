"""cSONiC MACsec tests with EOS/regular-SONiC compatibility guards."""

import ast
import logging
import shlex
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest


class FakeCsonicHost:
    pass


class FakeEosHost:
    pass


MODULE_PATH = Path(__file__).resolve().parents[2] / "macsec/macsec_config_helper.py"
TREE = ast.parse(MODULE_PATH.read_text())
FUNCTION_NAMES = {
    "_command_succeeded",
    "_command_diagnostic",
    "_runtime_port_name",
    "_run_required_csonic_command",
    "_csonic_config_db_hset",
    "_csonic_config_db_delete",
    "_csonic_config_db_hdel",
    "_csonic_macsec_profile_fields",
    "_supervisor_macsec_state",
    "_csonic_macsec_service_state",
    "_restore_csonic_hash_field",
    "_start_csonic_macsec_service",
    "_rollback_csonic_macsec_service",
    "_stop_csonic_macsec_service",
    "_unique_csonic_hosts",
    "_csonic_service_ready",
    "_csonic_interface_diagnostics",
    "set_macsec_profile",
    "is_macsec_configured",
    "delete_macsec_profile",
    "enable_macsec_port",
    "disable_macsec_port",
    "replace_macsec_port",
    "enable_macsec_feature",
    "disable_macsec_feature",
    "_wait_for_macsec_cleanup_with_vs_recovery",
    "_restore_macsec_feature_after_cleanup_recovery",
    "cleanup_macsec_configuration",
    "setup_macsec_configuration",
}
NODES = [
    node for node in TREE.body
    if (
        isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES
    ) or (
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "CSONIC_MACSEC_SUPERVISOR_CONFIG"
            for target in node.targets
        )
    )
]
NAMESPACE = {
    "CsonicHost": FakeCsonicHost,
    "EosHost": FakeEosHost,
    "Mapping": Mapping,
    "shlex": shlex,
    "logger": logging.getLogger(__name__),
    "time": MagicMock(),
}
exec(
    compile(ast.Module(body=NODES, type_ignores=[]), str(MODULE_PATH), "exec"),
    NAMESPACE,
)
ORIGINAL_NAMESPACE = NAMESPACE.copy()


@pytest.fixture(autouse=True)
def restore_namespace():
    NAMESPACE.clear()
    NAMESPACE.update(ORIGINAL_NAMESPACE)
    yield


set_macsec_profile = NAMESPACE["set_macsec_profile"]
delete_macsec_profile = NAMESPACE["delete_macsec_profile"]
enable_macsec_port = NAMESPACE["enable_macsec_port"]
disable_macsec_port = NAMESPACE["disable_macsec_port"]
enable_macsec_feature = NAMESPACE["enable_macsec_feature"]
disable_macsec_feature = NAMESPACE["disable_macsec_feature"]
setup_macsec_configuration = NAMESPACE["setup_macsec_configuration"]
cleanup_macsec_configuration = NAMESPACE["cleanup_macsec_configuration"]


class SonicHost:
    def __init__(self, *, multi_asic=False, facts=None):
        self.hostname = "sonic"
        self.is_multi_asic = multi_asic
        self.facts = facts or {"asic_type": "mellanox", "platform_asic": "vs"}
        self.command = MagicMock(return_value={"rc": 0, "stdout": "", "stdout_lines": []})
        self.shell = MagicMock(return_value={"rc": 0, "stdout": "", "stdout_lines": []})
        self.iface_macsec_ok = MagicMock(return_value=True)

    def num_asics(self):
        return 1

    def get_asic_namespace_list(self):
        return ["asic0", "asic1"]


class CsonicHost(FakeCsonicHost):
    def __init__(self):
        self.hostname = "csonic"
        self.container_name = "csonic_vm"
        self.vm_host_ip = None
        self.vm_host_user = None
        self.command = MagicMock(return_value={"rc": 0, "stdout": "", "stdout_lines": []})
        self.shell = MagicMock(return_value={"rc": 0, "stdout": "", "stdout_lines": []})
        self.iface_macsec_ok = MagicMock(return_value=True)
        self.set_ovs_macsec_member = MagicMock()


class EosHost(FakeEosHost):
    def __init__(self):
        self.hostname = "eos"
        self.eos_config = MagicMock()
        self.iface_macsec_ok = MagicMock(return_value=True)


PROFILE_ARGS = (
    "128_SCI", 64, "GCM-AES-128", "cak", "ckn", "security", "true", 0,
)


def test_regular_sonic_profile_command_is_legacy_command():
    host = SonicHost()

    set_macsec_profile(host, *PROFILE_ARGS)

    host.command.assert_called_once_with(
        "config macsec profile add 128_SCI  --priority 64"
        " --cipher_suite GCM-AES-128 --primary_cak cak --primary_ckn ckn"
        " --policy security --send_sci  --rekey_period 0")


def test_regular_multi_asic_profile_commands_are_unchanged():
    host = SonicHost(multi_asic=True)

    set_macsec_profile(host, *PROFILE_ARGS)

    assert host.command.call_args_list == [
        call("config macsec -n asic0 profile add 128_SCI  --priority 64"
             " --cipher_suite GCM-AES-128 --primary_cak cak --primary_ckn ckn"
             " --policy security --send_sci  --rekey_period 0"),
        call("config macsec -n asic1 profile add 128_SCI  --priority 64"
             " --cipher_suite GCM-AES-128 --primary_cak cak --primary_ckn ckn"
             " --policy security --send_sci  --rekey_period 0"),
    ]


def test_eos_profile_path_has_no_new_preflight_reads():
    host = EosHost()

    set_macsec_profile(host, *PROFILE_ARGS)

    host.eos_config.assert_called_once_with(
        lines=[
            "cipher aes128-gcm",
            "key ckn 7 cak",
            "mka key-server priority 64",
            "sci",
        ],
        parents=["mac security", "profile 128_SCI"],
    )
    assert not hasattr(host, "eos_command")


def test_csonic_profile_uses_direct_config_db_only():
    host = CsonicHost()

    set_macsec_profile(host, *PROFILE_ARGS)

    host.command.assert_called_once_with(
        "sonic-db-cli CONFIG_DB HSET 'MACSEC_PROFILE|128_SCI'"
        " priority 64 cipher_suite GCM-AES-128 primary_cak cak"
        " primary_ckn ckn policy security send_sci true rekey_period 0")


def test_csonic_no_sci_profile_applies_lldp_workaround():
    host = CsonicHost()

    set_macsec_profile(
        host, "128", 64, "GCM-AES-128", "cak", "ckn", "security", "false", 0)

    assert host.command.call_args_list[-1] == call(
        "lldpcli configure system bond-slave-src-mac-type real")


def test_regular_sonic_port_commands_are_legacy_commands():
    host = SonicHost(facts={"asic_type": "mellanox", "platform_asic": "vs"})
    NAMESPACE["get_portchannel"] = MagicMock(return_value={})
    NAMESPACE["find_portchannel_from_member"] = MagicMock(return_value=None)
    NAMESPACE["getns_prefix"] = MagicMock(return_value=" ")

    enable_macsec_port(host, "Ethernet0", "128_SCI")
    disable_macsec_port(host, "Ethernet0")

    assert host.command.call_args_list == [
        call("config macsec   port add Ethernet0 128_SCI"),
        call("config macsec   port del Ethernet0"),
    ]


def test_eos_port_commands_are_unchanged():
    host = EosHost()

    enable_macsec_port(host, "Ethernet1", "128_SCI")
    disable_macsec_port(host, "Ethernet1")

    assert host.eos_config.call_args_list == [
        call(lines=["mac security profile 128_SCI"],
             parents=["interface Ethernet1"]),
        call(lines=["no mac security profile"],
             parents=["interface Ethernet1"]),
    ]


def test_csonic_port_switch_is_explicitly_gated():
    host = CsonicHost()

    enable_macsec_port(host, "Ethernet1", "128_SCI")
    disable_macsec_port(host, "Ethernet1")

    assert host.command.call_args_list == [
        call("sonic-db-cli CONFIG_DB HSET 'PORT|Ethernet1' macsec 128_SCI"),
        call("sonic-db-cli CONFIG_DB HDEL 'PORT|Ethernet1' macsec"),
    ]
    assert host.set_ovs_macsec_member.call_args_list == [
        call("Ethernet1", True), call("Ethernet1", False)]


def test_setup_keeps_legacy_scheduling_and_sleep_trace():
    dut = SonicHost()
    nbr = SonicHost()
    ctrl_links = {
        "Ethernet0": {"host": nbr, "port": "Ethernet1"},
        "Ethernet4": {"host": nbr, "port": "Ethernet5"},
    }
    submitted = []
    NAMESPACE["submit_async_task"] = lambda target, args: submitted.append((target, args))
    NAMESPACE["wait_all_complete"] = MagicMock()
    NAMESPACE["wait_until"] = MagicMock(return_value=True)
    NAMESPACE["time"] = MagicMock()

    setup_macsec_configuration(
        dut, ctrl_links, "128", 64, "GCM-AES-128", "cak", "ckn",
        "security", "true", 0, {})

    assert submitted == [
        (set_macsec_profile, (dut, "128", 64, "GCM-AES-128", "cak", "ckn",
                              "security", "true", 0)),
        (set_macsec_profile, (nbr, "128", 63, "GCM-AES-128", "cak", "ckn",
                              "security", "true", 0)),
        (set_macsec_profile, (nbr, "128", 65, "GCM-AES-128", "cak", "ckn",
                              "security", "true", 0)),
        (enable_macsec_port, (dut, "Ethernet0", "128")),
        (enable_macsec_port, (nbr, "Ethernet1", "128")),
        (enable_macsec_port, (dut, "Ethernet4", "128")),
        (enable_macsec_port, (nbr, "Ethernet5", "128")),
    ]
    assert NAMESPACE["time"].sleep.call_args_list == [call(3), call(3), call(60)]
    assert NAMESPACE["wait_all_complete"].call_args_list == [
        call(timeout=180), call(timeout=180)]


def test_cleanup_keeps_legacy_scheduling_and_sleep_trace():
    dut = SonicHost()
    nbr = SonicHost()
    ctrl_links = {"Ethernet0": {"host": nbr, "port": "Ethernet1"}}
    submitted = []
    NAMESPACE["submit_async_task"] = lambda target, args: submitted.append((target, args))
    NAMESPACE["wait_all_complete"] = MagicMock()
    NAMESPACE["wait_for_macsec_cleanup"] = MagicMock(return_value=True)
    NAMESPACE["get_mka_session"] = MagicMock(return_value={})
    NAMESPACE["wait_until"] = MagicMock(return_value=True)
    NAMESPACE["time"] = MagicMock()

    cleanup_macsec_configuration(dut, ctrl_links, "128")

    assert submitted == [
        (disable_macsec_port, (dut, "Ethernet0")),
        (disable_macsec_port, (nbr, "Ethernet1")),
        (delete_macsec_profile, (dut, "128")),
        (delete_macsec_profile, (nbr, "128")),
    ]
    assert NAMESPACE["time"].sleep.call_args_list == [call(3)]
    assert NAMESPACE["wait_all_complete"].call_args_list == [
        call(timeout=300), call(timeout=300)]


def test_feature_enable_without_csonic_uses_only_legacy_path():
    dut = SonicHost()
    nbr = SonicHost()
    eos = EosHost()
    command = MagicMock()
    NAMESPACE["global_cmd"] = command
    NAMESPACE["wait_until"] = lambda timeout, interval, delay, predicate: predicate()
    dut.shell.side_effect = [
        {"stdout_lines": ["macsec"]},
        {"stdout_lines": ["macsecmgrd"]},
    ]
    nbr.shell.side_effect = [
        {"stdout_lines": ["macsec"]},
        {"stdout_lines": ["macsecmgrd"]},
    ]

    enable_macsec_feature(
        dut, {"sonic": {"host": nbr}, "eos": {"host": eos}})

    command.assert_called_once_with(
        dut, {"sonic": {"host": nbr}, "eos": {"host": eos}},
        "sudo config feature state macsec enabled")
    assert dut.shell.call_count == 2
    assert nbr.shell.call_count == 2
    assert not eos.eos_config.called


def test_feature_enable_adds_only_csonic_service_lifecycle():
    dut = SonicHost()
    host = CsonicHost()
    initial = {
        "state": "STOPPED",
        "config_exists": True,
        "post_state": "pass",
        "feature_state": "disabled",
    }
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["_csonic_macsec_service_state"] = MagicMock(return_value=initial)
    NAMESPACE["_start_csonic_macsec_service"] = MagicMock(return_value=True)
    NAMESPACE["_csonic_service_ready"] = MagicMock(return_value=True)
    NAMESPACE["wait_until"] = lambda timeout, interval, delay, predicate: predicate()
    dut.shell.side_effect = [
        {"stdout_lines": ["macsec"]},
        {"stdout_lines": ["macsecmgrd"]},
    ]

    enable_macsec_feature(dut, {"csonic": {"host": host}})

    NAMESPACE["global_cmd"].assert_called_once()
    NAMESPACE["_start_csonic_macsec_service"].assert_called_once_with(
        host, initial)
    NAMESPACE["_csonic_service_ready"].assert_called_once_with(host)


def test_disable_without_csonic_is_legacy_global_command_only():
    dut = SonicHost()
    nbr = SonicHost()
    NAMESPACE["global_cmd"] = MagicMock()
    NAMESPACE["_stop_csonic_macsec_service"] = MagicMock()

    disable_macsec_feature(dut, {"sonic": {"host": nbr}})

    NAMESPACE["global_cmd"].assert_called_once_with(
        dut, {"sonic": {"host": nbr}},
        "sudo config feature state macsec disabled")
    NAMESPACE["_stop_csonic_macsec_service"].assert_not_called()


def test_csonic_cleanup_timeout_never_reloads_container():
    host = CsonicHost()
    NAMESPACE["wait_for_macsec_cleanup"] = MagicMock(return_value=False)
    NAMESPACE["_csonic_interface_diagnostics"] = MagicMock(return_value={})
    NAMESPACE["config_reload"] = MagicMock()

    with pytest.raises(AssertionError, match="cSONiC"):
        NAMESPACE["_wait_for_macsec_cleanup_with_vs_recovery"](
            host, ["Ethernet1"], is_dut=False)

    NAMESPACE["config_reload"].assert_not_called()


def test_shared_transaction_helpers_were_removed_from_production_scope():
    names = {
        node.name for node in TREE.body if isinstance(node, ast.FunctionDef)
    }

    assert "_macsec_profile_snapshot" not in names
    assert "_rollback_macsec_configuration" not in names
    assert "_wait_for_macsec_tasks" not in names
