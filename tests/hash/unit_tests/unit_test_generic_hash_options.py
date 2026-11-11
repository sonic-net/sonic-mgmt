"""Hardware-independent coverage for generic hash prerequisites and recovery."""

import ast
from collections import deque
from contextlib import contextmanager, nullcontext
import logging
import math
import random
import re
import shlex
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

pytest_plugins = ["pytester"]


@pytest.fixture
def helper():
    path = Path(__file__).resolve().parents[1] / "generic_hash_helper.py"
    tree = ast.parse(path.read_text())
    names = {
        "get_asic_type", "validate_vpp_hash_metadata", "get_hash_fields_from_option",
        "get_hash_algorithm_from_option", "get_reboot_type_from_option",
        "get_ip_version_from_option", "get_encap_type_from_option",
        "preserve_hash_config", "restore_hash_config", "restore_init_hash_config", "restore_interfaces",
        "track_hash_interface", "check_hash_interfaces",
        "running_config_matches", "get_hash_balance_expectations", "generate_test_params",
        "remove_add_portchannel_member", "shutdown_interface", "startup_interface",
        "flap_interfaces", "ignore_expected_vpp_link_churn",
        "check_vpp_fib_paths", "check_vpp_nexthop_paths",
    }
    nodes = [
        node for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name in names)
        or (isinstance(node, ast.Assign)
            and all(isinstance(target, ast.Name) and target.id.isupper() for target in node.targets))
    ]
    test_tree = ast.parse((path.parent / "test_generic_hash.py").read_text())
    for name in ("fine_params", "pytest_generate_tests"):
        function = next(node for node in test_tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == name)
        function.decorator_list = []
        nodes.append(function)
    metadata = {"dut": {"asic_type": "vpp"}}
    tbinfo = {"duts": ["dut"], "topo": {"name": "t1-lag"}}
    facts = {"asic_type": "vpp"}
    request = SimpleNamespace(config=SimpleNamespace(cache=SimpleNamespace(get=Mock(return_value=facts))),
                              fixturenames=[], node=SimpleNamespace())
    namespace = {
        "pytest": pytest,
        "get_testbed_metadata": Mock(return_value=metadata),
        "get_tbinfo": Mock(return_value=("testbed", tbinfo)),
        "get_specified_duts": Mock(return_value=tbinfo["duts"]),
        "get_basic_facts": Mock(),
        "random": random,
        "contextmanager": contextmanager,
        "shlex": shlex,
        "re": re,
        "logger": Mock(),
        "get_global_hash_config": Mock(return_value=([], "N/A", [], "N/A")),
        "config_reload": Mock(),
        "wait_until": Mock(return_value=True),
        "interfaces_to_startup": [],
        "pytest_assert": lambda condition, message: None if condition else pytest.fail(message),
        "get_ip_range": Mock(return_value=(["8.0.0.0", "8.255.255.255"], ["9.0.0.0", "9.255.255.255"], [], [])),
        "get_ptf_port_indices": Mock(return_value=([0], [[2, 3], [4, 5]])),
        "get_updated_balancing_test_times_and_range": Mock(return_value=(480, 0.3)),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return SimpleNamespace(namespace=namespace, metadata=metadata, tbinfo=tbinfo, facts=facts, request=request)


@pytest.mark.parametrize("metadata", [
    None, {}, {"old-dut": {"asic_type": "vpp"}}, {"dut": {}}, {"dut": {"asic_type": ""}},
])
def test_target_runtime_rejects_missing_metadata_before_configuration(helper, metadata):
    helper.namespace["get_testbed_metadata"].return_value = metadata
    dut = Mock(facts={"asic_type": "vpp"})
    with pytest.raises(pytest.fail.Exception, match="test_update_testbed_metadata"):
        next(helper.namespace["restore_init_hash_config"].__wrapped__(dut, None, helper.tbinfo, helper.request))
    helper.namespace["get_global_hash_config"].assert_not_called()
    dut.shell.assert_not_called()


@pytest.mark.parametrize("asic", ["vs", "mellanox", "unknown"])
def test_target_runtime_rejects_metadata_that_disagrees_with_the_dut(helper, asic):
    helper.metadata["dut"]["asic_type"] = asic
    dut = Mock(facts={"asic_type": "vpp"})
    with pytest.raises(pytest.fail.Exception, match="test_update_testbed_metadata"):
        next(helper.namespace["restore_init_hash_config"].__wrapped__(dut, None, helper.tbinfo, helper.request))
    helper.namespace["get_global_hash_config"].assert_not_called()
    dut.shell.assert_not_called()


@pytest.mark.parametrize("facts", [None, {}, {"asic_type": ""}])
def test_collection_with_metadata_does_not_require_live_dut_facts(helper, facts):
    helper.request.config.cache.get.return_value = facts
    assert helper.namespace["get_asic_type"](helper.request) == "vpp"
    helper.namespace["get_basic_facts"].assert_not_called()
    helper.request.config.cache.get.assert_not_called()


@pytest.mark.parametrize("topology", ["t0", "t1-lag"])
def test_offline_collection_preserves_legacy_defaults_without_metadata(helper, topology):
    helper.tbinfo["topo"]["name"] = topology
    helper.namespace["get_testbed_metadata"].return_value = None
    assert helper.namespace["get_asic_type"](helper.request) == "unknown"
    assert helper.namespace["get_hash_fields_from_option"](helper.request, "ecmp", "all") == (
        helper.namespace["HASH_CAPABILITIES"]["default"]["ecmp"])
    helper.namespace["get_basic_facts"].assert_not_called()
    helper.namespace["get_specified_duts"].assert_not_called()


@pytest.mark.parametrize("topology", ["t0", "t1-lag"])
def test_unselected_dut_does_not_require_metadata(helper, topology):
    helper.tbinfo["topo"]["name"] = topology
    helper.tbinfo["duts"].append("unselected-dut")
    helper.namespace["get_specified_duts"].return_value = ["dut"]
    assert helper.namespace["get_asic_type"](helper.request) == "vpp"
    helper.namespace["get_basic_facts"].assert_not_called()


def test_metadata_uses_current_duts_not_first_dictionary_entry(helper):
    helper.namespace["get_testbed_metadata"].return_value = {
        "old-dut": {"asic_type": "mellanox"}, **helper.metadata,
    }
    assert helper.namespace["get_asic_type"](helper.request) == "vpp"


def test_mixed_selected_dut_metadata_does_not_choose_arbitrary_capabilities(helper):
    helper.tbinfo["duts"].append("other-dut")
    helper.metadata["other-dut"] = {"asic_type": "mellanox"}
    with pytest.raises(pytest.fail.Exception, match="require vpp metadata"):
        helper.namespace["get_asic_type"](helper.request)


def test_t0_keeps_legacy_metadata_selection_without_querying_duts(helper):
    helper.tbinfo["topo"]["name"] = "t0"
    helper.namespace["get_testbed_metadata"].return_value = {
        "first-dut": {"asic_type": "mellanox"}, **helper.metadata,
    }
    assert helper.namespace["get_asic_type"](helper.request) == "mellanox"
    helper.namespace["get_specified_duts"].assert_not_called()
    helper.namespace["get_basic_facts"].assert_not_called()


@pytest.mark.parametrize("topology,asic,algorithms,reboots", [
    ("t0", "vpp", ["CRC"], ["cold", "reload"]),
    ("t1-lag", "vpp", ["CRC"], ["cold", "reload"]),
    ("t1-lag", "mellanox", ["CRC", "CRC_CCITT"], ["cold", "warm", "fast", "reload"]),
    ("t0", "broadcom", ["CRC", "CRC_CCITT", "RANDOM", "XOR"], ["cold", "warm", "fast", "reload"]),
])
def test_valid_platform_options_are_preserved(helper, topology, asic, algorithms, reboots):
    helper.tbinfo["topo"]["name"] = topology
    helper.metadata["dut"]["asic_type"] = asic
    helper.facts["asic_type"] = asic
    assert helper.namespace["get_hash_algorithm_from_option"](helper.request, "all") == algorithms
    assert helper.namespace["get_reboot_type_from_option"](helper.request, "all") == reboots
    fields = helper.namespace["HASH_CAPABILITIES"].get(asic, helper.namespace["HASH_CAPABILITIES"]["default"])
    for kind in ("ecmp", "lag"):
        assert helper.namespace["get_hash_fields_from_option"](helper.request, kind, "all") == fields[kind]


@pytest.mark.parametrize("reboot", ["warm", "fast", "watchdog"])
def test_vpp_explicit_reboot_cannot_bypass_supported_types(helper, reboot):
    assert helper.namespace["get_reboot_type_from_option"](helper.request, reboot) == [reboot]
    helper.request.fixturenames = ["reboot_type"]
    helper.request.getfixturevalue = Mock(return_value=reboot)
    dut = Mock(facts={"asic_type": "vpp"})
    with pytest.raises(pytest.fail.Exception, match="Supported reboot types: cold, reload"):
        next(helper.namespace["restore_init_hash_config"].__wrapped__(dut, None, helper.tbinfo, helper.request))
    helper.namespace["get_global_hash_config"].assert_not_called()
    dut.shell.assert_not_called()


@pytest.mark.parametrize("reboot", ["cold", "reload"])
def test_vpp_explicit_supported_reboot_is_preserved(helper, reboot):
    assert helper.namespace["get_reboot_type_from_option"](helper.request, reboot) == [reboot]


@pytest.mark.parametrize("topology", ["t0", "t1"])
@pytest.mark.parametrize("reboot", ["fast", "warm"])
def test_other_vpp_topologies_preserve_explicit_reboot_options(helper, topology, reboot):
    helper.tbinfo["topo"]["name"] = topology
    assert helper.namespace["get_reboot_type_from_option"](helper.request, reboot) == [reboot]


@pytest.mark.parametrize("topology", ["t0", "t1-lag"])
@pytest.mark.parametrize("reboot", ["fast", "warm"])
def test_non_reboot_collection_does_not_validate_irrelevant_reboot_option(helper, topology, reboot):
    helper.tbinfo["topo"]["name"] = topology
    options = {
        "--hash_field": "SRC_IP", "--algorithm": "CRC", "--ip_version": "ipv4",
        "--inner_ip_version": "ipv4", "--encap_type": "ipinip", "--reboot": reboot,
    }
    metafunc = SimpleNamespace(
        function=SimpleNamespace(__name__="test_hash_capability"),
        config=SimpleNamespace(getoption=options.__getitem__), fixturenames=[], parametrize=Mock())
    validate = Mock(side_effect=AssertionError("Non-reboot case requested reboot validation"))
    helper.namespace["get_reboot_type_from_option"] = validate
    helper.namespace["pytest_generate_tests"](metafunc)
    validate.assert_not_called()
    metafunc.parametrize.assert_not_called()


@pytest.fixture
def real_collector(helper, pytester, monkeypatch):
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    options = {}
    path = Path(__file__).resolve().parents[1] / "conftest.py"
    exec(compile(path.read_text(), str(path), "exec"), options)
    dut = Mock(facts={"asic_type": "vpp"})
    dut.shell.return_value = {"stdout": "/host/generic-hash.unit"}
    helper.namespace["running_config_matches"] = Mock(return_value=True)
    plugin = ModuleType("hash_collector")
    plugin.__dict__.update(
        pytest_addoption=options["pytest_addoption"],
        pytest_generate_tests=helper.namespace["pytest_generate_tests"],
        restore_init_hash_config=helper.namespace["restore_init_hash_config"],
        rand_selected_dut=pytest.fixture(name="rand_selected_dut")(lambda: dut),
        loganalyzer=pytest.fixture(name="loganalyzer")(lambda: None),
        tbinfo=pytest.fixture(name="tbinfo")(lambda: helper.tbinfo),
    )
    module = pytester.makepyfile("""
        def test_hash_capability():
            pass

        def test_algorithm_config():
            pass

        def test_reboot(reboot_type):
            pass
    """)

    def run(node, reboot, collect_only=False):
        args = [
            f"{module}::{node}", "--noconftest", "-q", "--algorithm", "CRC",
            "--hash_field", "SRC_IP", "--ip_version", "ipv4", "--inner_ip_version", "ipv4",
            "--encap_type", "ipinip", "--reboot", reboot,
        ]
        if collect_only:
            args.append("--collect-only")
        return pytester.runpytest_inprocess(*args, plugins=[plugin])

    return SimpleNamespace(run=run, dut=dut)


@pytest.mark.parametrize("topology", ["t0", "t1-lag"])
@pytest.mark.parametrize("reboot", ["fast", "warm"])
@pytest.mark.parametrize("node", ["test_hash_capability", "test_algorithm_config"])
def test_real_collection_filters_unselected_reboot_cases(helper, real_collector, topology, reboot, node):
    helper.tbinfo["topo"]["name"] = topology
    result = real_collector.run(node, reboot, collect_only=True)
    assert result.ret == pytest.ExitCode.OK
    result.stdout.fnmatch_lines(["*1 test collected*"])
    helper.namespace["get_global_hash_config"].assert_not_called()
    real_collector.dut.shell.assert_not_called()


@pytest.mark.parametrize("topology", ["t0", "t1-lag"])
@pytest.mark.parametrize("reboot", ["fast", "warm", "cold", "reload"])
def test_selected_reboot_setup_rejects_only_unsupported_target_modes(helper, real_collector, topology, reboot):
    helper.tbinfo["topo"]["name"] = topology
    result = real_collector.run("test_reboot", reboot)
    if topology == "t1-lag" and reboot in ("fast", "warm"):
        assert result.ret == pytest.ExitCode.TESTS_FAILED
        result.assert_outcomes(errors=1)
        result.stdout.fnmatch_lines(["*Supported reboot types: cold, reload*"])
        helper.namespace["get_global_hash_config"].assert_not_called()
        real_collector.dut.shell.assert_not_called()
    else:
        assert result.ret == pytest.ExitCode.OK
        result.assert_outcomes(passed=1)
        helper.namespace["get_global_hash_config"].assert_called_once()


@pytest.mark.parametrize("asic,topology,field,expected", [
    ("vpp", "t1-lag", "IP_PROTOCOL", (True, False)),
    ("vpp", "t0", "IP_PROTOCOL", (True, True)),
    ("vpp", "t1-lag", "SRC_IP", (True, True)),
    ("vpp", "t1-lag", "L4_DST_PORT", (True, True)),
    ("mellanox", "t1-lag", "IP_PROTOCOL", (True, True)),
])
def test_fixed_vpp_protocol_keeps_ecmp_but_not_lag_balance(helper, asic, topology, field, expected):
    assert helper.namespace["get_hash_balance_expectations"](asic, topology, field, True, True) == expected


def test_vpp_protocol_cannot_be_misreported_as_lag_only(helper):
    with pytest.raises(pytest.fail.Exception, match="does not support LAG"):
        helper.namespace["get_hash_balance_expectations"]("vpp", "t1-lag", "IP_PROTOCOL", False, True)


@pytest.mark.parametrize("name", ["test_lag_member_flap", "test_lag_member_remove_add"])
def test_only_vpp_protocol_member_disruption_is_skipped(helper, name):
    with pytest.raises(pytest.skip.Exception, match="not LAG-member entropy"):
        helper.namespace["fine_params"](
            "CRC-IP_PROTOCOL-ipv4-None-None", {"ecmp_algo": ["CRC"]},
            SimpleNamespace(node=SimpleNamespace(originalname=name)),
            SimpleNamespace(facts={"asic_type": "vpp"}), Mock(), helper.tbinfo)


@pytest.mark.parametrize("asic,topology,field,name,recorded", [
    ("vpp", "t1-lag", "IP_PROTOCOL", "test_ecmp_and_lag_hash", True),
    ("vpp", "t1-lag", "IP_PROTOCOL", "test_reboot", True),
    ("vpp", "t0", "IP_PROTOCOL", "test_lag_member_flap", False),
    ("vpp", "t1-lag", "SRC_IP", "test_lag_member_flap", False),
    ("mellanox", "t1-lag", "IP_PROTOCOL", "test_lag_member_flap", False),
])
def test_supported_cases_keep_their_parameters_and_report_scope(helper, asic, topology, field, name, recorded):
    params = f"CRC-{field}-ipv6-None-None"
    record = Mock()
    helper.tbinfo["topo"]["name"] = topology
    assert helper.namespace["fine_params"](
        params, {"ecmp_algo": ["CRC"]}, SimpleNamespace(node=SimpleNamespace(originalname=name)),
        SimpleNamespace(facts={"asic_type": asic}), record, helper.tbinfo) == params
    assert record.called == recorded


@pytest.mark.parametrize("asic,topology,field,finite", [
    ("vpp", "t1-lag", "IP_PROTOCOL", True),
    ("vpp", "t0", "IP_PROTOCOL", False),
    ("mellanox", "t1-lag", "IP_PROTOCOL", False),
    ("vpp", "t1-lag", "SRC_IP", False),
    ("vpp", "t1-lag", "DST_IP", False),
    ("vpp", "t1-lag", "L4_SRC_PORT", False),
    ("vpp", "t1-lag", "L4_DST_PORT", False),
])
def test_finite_domain_parameters_are_opt_in_and_preserve_other_bounds(helper, asic, topology, field, finite):
    helper.tbinfo["topo"]["name"] = topology
    params = helper.namespace["generate_test_params"](
        SimpleNamespace(facts={"asic_type": asic, "router_mac": "00:11:22:33:44:55"}),
        helper.tbinfo, {}, field, "ipv4", "None", "None", {}, {}, True, True)
    assert params.get("protocol_domain_validation", False) == finite
    assert params["ecmp_hash"] and params["lag_hash"] == (not finite)
    assert params["balancing_range"] == 0.3
    assert params["balancing_test_times"] == 480


@pytest.fixture
def recovery(helper):
    dut = Mock()
    dut.shell.return_value = {"stdout": "/host/generic-hash.unit"}
    helper.namespace["running_config_matches"] = Mock(side_effect=[False, True])
    return dut


def test_absent_hash_config_is_reloaded_even_after_test_failure(helper, recovery):
    with pytest.raises(RuntimeError, match="packet failure"):
        with helper.namespace["preserve_hash_config"](recovery):
            raise RuntimeError("packet failure")
    helper.namespace["config_reload"].assert_called_once_with(
        recovery, safe_reload=True, check_intf_up_ports=True, ignore_loganalyzer=None)
    commands = [call.args[0] for call in recovery.shell.call_args_list]
    assert "cp /host/generic-hash.unit/running.json /etc/sonic/config_db.json" in commands
    assert commands[-2].startswith("cp -p /host/generic-hash.unit/config_db.json /etc/sonic/config_db.json")
    assert commands[-1].startswith("rm ")


def test_reload_log_boundary_does_not_cover_test_execution(helper, recovery):
    analyzers = {"dut": Mock()}
    with helper.namespace["preserve_hash_config"](recovery, analyzers):
        helper.namespace["config_reload"].assert_not_called()
        assert analyzers["dut"].mock_calls == []
    helper.namespace["config_reload"].assert_called_once_with(
        recovery, safe_reload=True, check_intf_up_ports=True, ignore_loganalyzer=analyzers)


def test_saved_config_is_restored_and_snapshots_retained_when_reload_fails(helper, recovery):
    helper.namespace["config_reload"].side_effect = RuntimeError("reload failure")
    with pytest.raises(RuntimeError, match="reload failure"):
        with helper.namespace["preserve_hash_config"](recovery):
            pass
    commands = [call.args[0] for call in recovery.shell.call_args_list]
    assert commands[-1].startswith("cp -p /host/generic-hash.unit/config_db.json /etc/sonic/config_db.json")
    assert not any(command.startswith("rm ") for command in commands)


def test_failed_hash_setter_still_recovers_the_running_snapshot(helper, recovery):
    helper.namespace["get_global_hash_config"].return_value = (["SRC_IP"], "CRC", ["DST_IP"], "CRC")
    recovery.set_switch_hash_global.side_effect = RuntimeError("setter failure")
    with pytest.raises(RuntimeError, match="setter failure"):
        with helper.namespace["preserve_hash_config"](recovery):
            pass
    helper.namespace["config_reload"].assert_called_once()
    assert recovery.shell.call_args.args[0].startswith("cp -p ")


def test_initially_configured_hash_uses_setters_without_unnecessary_reload(helper, recovery):
    helper.namespace["get_global_hash_config"].return_value = (["SRC_IP"], "CRC", ["DST_IP"], "CRC")
    helper.namespace["running_config_matches"].side_effect = [True]
    with helper.namespace["preserve_hash_config"](recovery):
        pass
    assert recovery.set_switch_hash_global.call_count == 2
    assert recovery.set_switch_hash_global_algorithm.call_count == 2
    helper.namespace["config_reload"].assert_not_called()


@pytest.mark.parametrize("asic,topology", [("vpp", "t0"), ("mellanox", "t1-lag")])
def test_other_platforms_keep_existing_hash_only_recovery(helper, recovery, asic, topology):
    helper.namespace["get_global_hash_config"].return_value = (["SRC_IP"], "CRC", ["DST_IP"], "CRC")
    helper.tbinfo["topo"]["name"] = topology
    recovery.facts = {"asic_type": asic}
    fixture = helper.namespace["restore_init_hash_config"].__wrapped__(
        recovery, None, helper.tbinfo, helper.request)
    next(fixture)
    with pytest.raises(StopIteration):
        next(fixture)
    assert recovery.set_switch_hash_global.call_count == 2
    assert recovery.set_switch_hash_global_algorithm.call_count == 2
    recovery.shell.assert_not_called()
    helper.namespace["config_reload"].assert_not_called()


def test_unrestored_config_is_an_error_not_success(helper, recovery):
    helper.namespace["running_config_matches"].side_effect = [False, False]
    with pytest.raises(pytest.fail.Exception, match="snapshots remain"):
        with helper.namespace["preserve_hash_config"](recovery):
            pass
    assert recovery.shell.call_args.args[0].startswith("cp -p ")


@pytest.fixture
def disruption(helper, recovery):
    recovery.facts = {"asic_type": "vpp"}
    config = {
        "PORT": {"Ethernet0": {"admin_status": "up"}},
        "PORTCHANNEL": {"PortChannel1": {"admin_status": "up"}},
        "PORTCHANNEL_MEMBER": {"PortChannel1": {"Ethernet0": {}, "Ethernet4": {}}},
    }
    recovery.get_running_config_facts.return_value = config
    recovery.is_interface_status_up.return_value = True
    ports = {port: {"link": {"up": True}, "runner": {"selected": True}}
             for port in ("Ethernet0", "Ethernet4")}
    recovery.get_port_channel_status.return_value = {"ports": ports}

    def shell(command):
        if command == "config portchannel member del PortChannel1 Ethernet0":
            del config["PORTCHANNEL_MEMBER"]["PortChannel1"]["Ethernet0"]
        elif command == "config portchannel member add PortChannel1 Ethernet0":
            config["PORTCHANNEL_MEMBER"]["PortChannel1"]["Ethernet0"] = {}
        return {"stdout": "/host/generic-hash.unit", "rc": 0}

    def reload(*args, **kwargs):
        recovery.is_interface_status_up.return_value = True
        ports["Ethernet0"] = {"link": {"up": True}, "runner": {"selected": True}}

    recovery.shell.side_effect = shell
    helper.namespace["running_config_matches"] = Mock(return_value=True)
    helper.namespace["config_reload"].side_effect = reload
    helper.namespace["wait_until"] = lambda timeout, interval, delay, predicate, *args: bool(predicate(*args))
    return recovery


@pytest.mark.parametrize("interface", ["Ethernet0", "PortChannel1"])
def test_post_startup_failure_reloads_even_when_config_matches(helper, disruption, interface):
    """Keep operational failure visible after startup empties the administrative cleanup list."""
    disruption.is_interface_status_up.return_value = False
    with pytest.raises(pytest.fail.Exception, match="not up after the flapping"):
        with helper.namespace["preserve_hash_config"](disruption) as state:
            helper.namespace["flap_interfaces"](
                disruption, [interface], times=1, tbinfo=helper.tbinfo, recovery=state)
    assert helper.namespace["interfaces_to_startup"] == []
    assert interface in state["interfaces"]
    helper.namespace["config_reload"].assert_called_once()
    disruption.get_port_channel_status.assert_called_with("PortChannel1")
    assert disruption.shell.call_args.args[0].startswith("rm ")


@pytest.mark.parametrize("fault", ["absent", "unselected", "link_down"])
def test_aggregate_up_cannot_hide_a_missing_active_member(helper, disruption, fault):
    """Require the selected member, not only its surviving PortChannel, before proceeding."""
    ports = disruption.get_port_channel_status.return_value["ports"]
    if fault == "absent":
        del ports["Ethernet0"]
    elif fault == "unselected":
        ports["Ethernet0"]["runner"]["selected"] = False
    else:
        ports["Ethernet0"]["link"]["up"] = False
    with pytest.raises(pytest.fail.Exception, match="Ethernet0 is not up and selected"):
        with helper.namespace["preserve_hash_config"](disruption) as state:
            helper.namespace["remove_add_portchannel_member"](
                disruption, "Ethernet0", "PortChannel1", tbinfo=helper.tbinfo, recovery=state)
    assert disruption.is_interface_status_up.return_value
    helper.namespace["config_reload"].assert_called_once()


def test_member_readiness_waits_for_selection_without_unnecessary_reload(helper, disruption):
    """A member that rejoins during the wait is ready without a recovery reload."""
    port = disruption.get_port_channel_status.return_value["ports"]["Ethernet0"]
    port["runner"]["selected"] = False
    observed = []

    def wait(timeout, interval, delay, predicate, *args):
        ready = bool(predicate(*args))
        if predicate is helper.namespace["check_hash_interfaces"] and not ready:
            observed.append(ready)
            port["runner"]["selected"] = True
            ready = bool(predicate(*args))
            observed.append(ready)
        return ready

    helper.namespace["wait_until"] = wait
    with helper.namespace["preserve_hash_config"](disruption) as state:
        helper.namespace["remove_add_portchannel_member"](
            disruption, "Ethernet0", "PortChannel1", tbinfo=helper.tbinfo, recovery=state)
    assert observed == [False, True]
    helper.namespace["config_reload"].assert_not_called()


@pytest.mark.parametrize("failure", ["delete", "add", "membership_read"])
def test_member_cleanup_errors_force_recovery_with_equal_config(helper, disruption, failure):
    """Retain the disrupted member even when mutation or membership inspection raises."""
    shell = disruption.shell.side_effect

    def fail_command(command):
        result = shell(command)
        if command.startswith(f"config portchannel member {'del' if failure == 'delete' else 'add'} "):
            raise RuntimeError(f"{failure} response lost")
        return result

    if failure == "membership_read":
        config = disruption.get_running_config_facts.return_value
        disruption.get_running_config_facts.side_effect = [config, RuntimeError("membership_read response lost")]
    else:
        disruption.shell.side_effect = fail_command
    with pytest.raises(RuntimeError, match=f"{failure} response lost"):
        with helper.namespace["preserve_hash_config"](disruption) as state:
            helper.namespace["remove_add_portchannel_member"](
                disruption, "Ethernet0", "PortChannel1", tbinfo=helper.tbinfo, recovery=state)
    assert ("PortChannel1", "Ethernet0") in state["members"]
    helper.namespace["config_reload"].assert_called_once()


@pytest.mark.parametrize("recovery_succeeds", [True, False])
def test_teardown_checks_operational_health_and_retains_failed_snapshots(helper, disruption, recovery_succeeds):
    """A matching configuration never hides operational damage at teardown."""
    if not recovery_succeeds:
        helper.namespace["config_reload"].side_effect = None
    with nullcontext() if recovery_succeeds else pytest.raises(pytest.fail.Exception, match="snapshots remain"):
        with helper.namespace["preserve_hash_config"](disruption) as state:
            helper.namespace["shutdown_interface"](
                disruption, "Ethernet0", tbinfo=helper.tbinfo, recovery=state)
            helper.namespace["startup_interface"](disruption, "Ethernet0")
            disruption.is_interface_status_up.return_value = False
    helper.namespace["config_reload"].assert_called_once()
    commands = [call.args[0] for call in disruption.shell.call_args_list]
    assert any(command.startswith("cp -p /host/generic-hash.unit/config_db.json") for command in commands)
    assert any(command.startswith("rm ") for command in commands) == recovery_succeeds
    with helper.namespace["preserve_hash_config"](disruption) as next_state:
        assert not next_state["interfaces"] and not next_state["members"] and not next_state["failed"]


@pytest.mark.parametrize("failure", ["oper_up", "later_convergence"])
def test_actual_fixture_teardown_recovers_failed_disruption(helper, disruption, pytester, monkeypatch, failure):
    """Use pytest call reports and real finalizers, which do not receive the test exception."""
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    if failure == "oper_up":
        disruption.is_interface_status_up.return_value = False
    events = []
    helper.namespace["logger"].info.side_effect = lambda message, *args: events.append(message)
    reload = helper.namespace["config_reload"].side_effect

    def recover(*args, **kwargs):
        events.append("reload")
        reload(*args, **kwargs)

    @pytest.hookimpl(hookwrapper=True)
    def report(item, call):
        outcome = yield
        result = outcome.get_result()
        setattr(item, "rep_" + result.when, result)

    helper.namespace["config_reload"].side_effect = recover
    plugin = ModuleType("hash_disruption_recovery")
    plugin.__dict__.update(
        restore_init_hash_config=helper.namespace["restore_init_hash_config"],
        restore_interfaces=helper.namespace["restore_interfaces"],
        rand_selected_dut=pytest.fixture(name="rand_selected_dut")(lambda: disruption),
        loganalyzer=pytest.fixture(name="loganalyzer")(lambda: None),
        tbinfo=pytest.fixture(name="tbinfo")(lambda: helper.tbinfo),
        helpers=pytest.fixture(name="helpers")(lambda: helper.namespace),
        pytest_runtest_makereport=report,
    )
    module = pytester.makepyfile("""
        def test_disruption(rand_selected_dut, tbinfo, helpers, restore_interfaces, restore_init_hash_config):
            helpers["flap_interfaces"](
                rand_selected_dut, ["Ethernet0"], times=1, tbinfo=tbinfo, recovery=restore_init_hash_config)
            raise RuntimeError("later convergence failed")
    """)
    result = pytester.runpytest_inprocess(str(module), "--noconftest", "-p", "no:cacheprovider", "-q", plugins=[plugin])
    result.assert_outcomes(failed=1)
    helper.namespace["config_reload"].assert_called_once()
    assert events.index("Startup the interfaces which were shutdown during the test") < events.index("reload")
    disruption.get_port_channel_status.assert_called_with("PortChannel1")


def test_member_is_added_back_if_delete_applies_then_raises(helper):
    dut = Mock(facts={"asic_type": "vpp"})
    dut.get_running_config_facts.side_effect = [
        {"PORTCHANNEL_MEMBER": {"PortChannel1": {"Ethernet0": {}}}},
        {"PORTCHANNEL_MEMBER": {"PortChannel1": {}}},
    ]
    dut.shell.side_effect = [RuntimeError("delete response lost"), {"rc": 0}]
    with pytest.raises(RuntimeError, match="delete response lost"):
        helper.namespace["remove_add_portchannel_member"](dut, "Ethernet0", "PortChannel1", tbinfo=helper.tbinfo)
    assert dut.shell.call_args.args[0] == "config portchannel member add PortChannel1 Ethernet0"


def test_failed_delete_does_not_add_an_existing_member(helper):
    dut = Mock(facts={"asic_type": "vpp"})
    dut.get_running_config_facts.return_value = {
        "PORTCHANNEL_MEMBER": {"PortChannel1": {"Ethernet0": {}}}}
    dut.shell.side_effect = RuntimeError("delete failed")
    with pytest.raises(RuntimeError, match="delete failed"):
        helper.namespace["remove_add_portchannel_member"](dut, "Ethernet0", "PortChannel1", tbinfo=helper.tbinfo)
    dut.shell.assert_called_once()


@pytest.mark.parametrize("admin_status", ["down", None])
def test_initially_down_interface_is_not_flapped(helper, admin_status):
    dut = Mock(facts={"asic_type": "vpp"})
    dut.get_running_config_facts.return_value = {"PORT": {"Ethernet0": {"admin_status": admin_status}}}
    with pytest.raises(pytest.fail.Exception, match="initially administratively down"):
        helper.namespace["shutdown_interface"](dut, "Ethernet0", tbinfo=helper.tbinfo)
    dut.shutdown.assert_not_called()
    assert helper.namespace["interfaces_to_startup"] == []


def test_interface_is_tracked_before_shutdown_can_fail(helper):
    dut = Mock(facts={"asic_type": "vpp"})
    dut.get_running_config_facts.return_value = {"PORTCHANNEL": {"PortChannel1": {"admin_status": "up"}}}
    dut.shutdown.side_effect = RuntimeError("shutdown response lost")
    with pytest.raises(RuntimeError, match="shutdown response lost"):
        helper.namespace["shutdown_interface"](dut, "PortChannel1", tbinfo=helper.tbinfo)
    assert helper.namespace["interfaces_to_startup"] == ["PortChannel1"]


@pytest.mark.parametrize("asic,topology", [("vpp", "t0"), ("mellanox", "t1-lag")])
def test_non_target_disruption_helpers_preserve_legacy_commands_without_new_preconditions(helper, asic, topology):
    dut = Mock(facts={"asic_type": asic})
    helper.tbinfo["topo"]["name"] = topology
    helper.namespace["shutdown_interface"](dut, "Ethernet0", tbinfo=helper.tbinfo)
    dut.shutdown.assert_called_once_with("Ethernet0")
    assert helper.namespace["interfaces_to_startup"] == ["Ethernet0"]
    helper.namespace["remove_add_portchannel_member"](dut, "Ethernet0", "PortChannel1", tbinfo=helper.tbinfo)
    assert [call.args[0] for call in dut.shell.call_args_list] == [
        "config portchannel member del PortChannel1 Ethernet0",
        "config portchannel member add PortChannel1 Ethernet0",
    ]
    dut.get_running_config_facts.assert_not_called()


@pytest.mark.parametrize("topology,tracked", [("t0", []), ("t1-lag", ["Ethernet0"])])
def test_flap_propagates_recovery_scope_when_shutdown_fails(helper, topology, tracked):
    helper.tbinfo["topo"]["name"] = topology
    dut = Mock(facts={"asic_type": "vpp"})
    dut.get_running_config_facts.return_value = {"PORT": {"Ethernet0": {"admin_status": "up"}}}
    dut.shutdown.side_effect = RuntimeError("shutdown failed")
    with pytest.raises(RuntimeError, match="shutdown failed"):
        helper.namespace["flap_interfaces"](dut, ["Ethernet0"], times=1, tbinfo=helper.tbinfo)
    assert helper.namespace["interfaces_to_startup"] == tracked


@pytest.mark.parametrize("asic,topology,enabled", [
    ("vpp", "t1-lag", True), ("vpp", "t0", False), ("mellanox", "t1-lag", False),
    ("vpp", "t1", False), ("vpp", "t2", False), ("mellanox", "t0", False),
])
def test_expected_churn_is_limited_to_target_platform_and_selected_ports(helper, asic, topology, enabled):
    dut = SimpleNamespace(hostname="dut", facts={"asic_type": asic})
    helper.tbinfo["topo"]["name"] = topology
    analyzer = SimpleNamespace(ignore_regex=[])
    helper.namespace["ignore_expected_vpp_link_churn"](
        dut, helper.tbinfo, {"dut": analyzer}, ["Ethernet56"])
    assert bool(analyzer.ignore_regex) == enabled
    if enabled:
        pattern = analyzer.ignore_regex[0]
        message = "ERR syncd#syncd#syncd: :- syncOnLinkMsg: skipping newlink for Ethernet56, name not found in map"
        assert re.search(pattern, message)
        assert re.search(pattern, message.replace(": :- ", ": message repeated 2 times: [ :- ") + "]")
        assert not re.search(pattern, message.replace("Ethernet56", "Ethernet60"))
        assert not re.search(pattern, message.replace("name not found in map", "failed to update port"))
        assert not re.search(pattern, message + "; another error")
        assert not re.search(pattern, message.replace("syncd", "swss"))


def test_expected_churn_does_not_require_enabled_loganalyzer(helper):
    helper.namespace["ignore_expected_vpp_link_churn"](
        SimpleNamespace(hostname="dut", facts={"asic_type": "vpp"}), helper.tbinfo, None, ["Ethernet56"])


def forwarding_output(ip_version, count, extra_buckets=()):
    # uRPF length and the inactive drop source are deliberately not the forwarding count.
    lines = ["API src-flags:added,contributing,active,",
             "  path-list:[388] uPRF-list:306 len:8 itfs:[65, 66, 67, 68, 69, 70, 71, 72]",
             "default-route entry-flags:drop,",
             "  path-list:[0] flags:drop, uPRF-list:0 len:0 itfs:[]",
             "forwarding: unicast-chain",
             "  [@0]: dpo-load-balance:"]
    for index in range(count):
        address = f"fc00::{index + 1:x}" if ip_version == "ipv6" else f"10.0.0.{index + 1}"
        lines.append(f"    [{index}] [@5]: {ip_version} via {address} BondEthernet{index}: mtu:9100")
    lines.extend(extra_buckets)
    return "\n".join(lines)


@pytest.mark.parametrize("ip_version,cli,prefix", [("ipv4", "ip", "0.0.0.0/0"), ("ipv6", "ip6", "::/0")])
def test_nexthop_readiness_checks_packet_family_and_exact_forwarding_count(helper, ip_version, cli, prefix):
    dut = Mock(facts={"asic_type": "vpp"})
    check = helper.namespace["check_vpp_nexthop_paths"]
    for actual, expected, ready in [
            (4, 3, False), (3, 3, True), (3, 4, False),
            (8, 7, False), (6, 7, False), (7, 7, True), (7, 8, False), (8, 8, True)]:
        dut.shell.return_value = {"rc": 0, "stdout": forwarding_output(ip_version, actual)}
        assert check(dut, helper.tbinfo, expected, ip_version) is ready
    assert all(call.args[0] == f"docker exec syncd vppctl show {cli} fib {prefix}"
               for call in dut.shell.call_args_list)


def test_repeated_forwarding_buckets_are_not_extra_nexthops(helper):
    dut = Mock(facts={"asic_type": "vpp"})
    dut.shell.return_value = {
        "rc": 0, "stdout": forwarding_output("ipv6", 7, [
            "    [7] [@5]: ipv6 via fc00::1 BondEthernet0: mtu:9100"])}
    assert helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, 7, "ipv6")
    assert not helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, 8, "ipv6")


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
@pytest.mark.parametrize("path_count", [3, 7])
def test_collapsed_bucket_ranges_count_distinct_nexthops(helper, ip_version, path_count):
    output = forwarding_output(ip_version, path_count)
    ranges = [(0, 1), (2, 2), (3, 3)] if path_count == 3 else [
        (0, 9), (10, 18), (19, 27), (28, 36), (37, 45), (46, 54), (55, 63)]
    for index, (start, end) in reversed(list(enumerate(ranges))):
        bucket = str(start) if start == end else f"{start}-{end}"
        output = output.replace(f"[{index}] [@5]", f"[{bucket}] [@5]")
    dut = Mock(facts={"asic_type": "vpp"})
    dut.shell.return_value = {"rc": 0, "stdout": output}
    assert helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, path_count, ip_version)
    assert not helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, path_count + 1, ip_version)
    dut.shell.return_value["stdout"] += "\n    [64-65] [@0]: dpo-drop ip6"
    assert not helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, path_count, ip_version)


@pytest.mark.parametrize("output,rc", [
    ("path-list:[388] len:7", 0),
    ("forwarding: UNRESOLVED", 0),
    (forwarding_output("ipv6", 7, ["    [7] [@0]: dpo-drop ip6"]), 0),
    (forwarding_output("ipv4", 7), 0),
    (forwarding_output("ipv6", 7) + "\nforwarding: another-table", 0),
    (forwarding_output("ipv6", 7), 1),
])
def test_unready_or_ambiguous_forwarding_cannot_pass(helper, output, rc):
    dut = Mock(facts={"asic_type": "vpp"})
    dut.shell.return_value = {"rc": rc, "stdout": output}
    assert not helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, 7, "ipv6")


@pytest.mark.parametrize("asic,topology", [
    ("vpp", "t0"), ("vpp", "t1"), ("vpp", "t2"), ("mellanox", "t1-lag"),
])
@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
def test_non_target_nexthop_check_keeps_legacy_ipv4_urpf_minimum(helper, asic, topology, ip_version):
    dut = Mock(facts={"asic_type": asic})
    helper.tbinfo["topo"]["name"] = topology
    dut.shell.return_value = {"rc": 0, "stdout": forwarding_output("ipv4", 3)}
    assert helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, 7, ip_version)
    assert not helper.namespace["check_vpp_nexthop_paths"](dut, helper.tbinfo, 9, ip_version)
    assert [call.args[0] for call in dut.shell.call_args_list] == [
        "docker exec syncd vppctl show ip fib 0.0.0.0/0",
        "docker exec syncd vppctl show ip fib 0.0.0.0/0",
    ]
    assert all(call.kwargs == {"module_ignore_errors": True} for call in dut.shell.call_args_list)


@pytest.mark.parametrize("ip_version", ["ipv4", "ipv6"])
@pytest.mark.parametrize("withdraw_ready", [True, False])
@pytest.mark.parametrize("topology", ["t0", "t1-lag"])
def test_nexthop_case_preserves_topology_scoped_readiness_and_logs(helper, ip_version, withdraw_ready, topology):
    helper.tbinfo["topo"]["name"] = topology
    path = Path(__file__).resolve().parents[1] / "test_generic_hash.py"
    function = next(node for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == "test_nexthop_flap")
    namespace = helper.namespace.copy()
    for name in ("skip_unsupported_field_for_ecmp_test", "config_all_hash_fields", "get_diff_hash_algorithm",
                 "config_all_hash_algorithm", "check_global_hash_config", "check_global_hash_algorithm",
                 "shutdown_interface", "startup_interface", "flap_interfaces",
                 "is_bgp_session_established", "ptf_runner"):
        namespace[name] = Mock()
    namespace["ignore_expected_vpp_link_churn"] = Mock(wraps=namespace["ignore_expected_vpp_link_churn"])
    uplinks = {"PortChannel1": ["Ethernet0"], "PortChannel2": ["Ethernet4"]}
    namespace.update(
        allure=SimpleNamespace(step=lambda _: nullcontext()),
        random=SimpleNamespace(choice=lambda items: items[0]),
        check_default_route=Mock(return_value=True),
        get_interfaces_for_test=Mock(return_value=(uplinks, ["Ethernet8"])),
        generate_test_params=Mock(return_value={"expected_port_groups": [[0], [1]]}),
        get_ptf_port_indices=Mock(return_value=([2], [[1]])),
        PTF_LOG_PATH="unused.log",
    )
    check = namespace["check_vpp_nexthop_paths"]
    readiness_calls = []

    def wait_until(_timeout, _interval, _delay, predicate, *args):
        if predicate is check:
            readiness_calls.append(args)
            expected = args[2]
            ready = expected != 1 or withdraw_ready
            output = forwarding_output(ip_version, expected if ready else 0)
            urpf_count = expected + 1 if ready else 0
            dut.shell.return_value = {"rc": 0, "stdout": output.replace("len:8", f"len:{urpf_count}")}
            return predicate(*args)
        return True

    namespace["wait_until"] = wait_until
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    dut = Mock(hostname="dut", facts={"asic_type": "vpp"})
    dut.show_and_parse.return_value = [{"interface": "PortChannel1", "neighbor ip": "10.0.0.1"}]
    analyzer = SimpleNamespace(ignore_regex=["existing-ignore"])
    loganalyzer = {"dut": analyzer}
    with nullcontext() if withdraw_ready else pytest.raises(pytest.fail.Exception, match="expected 1 paths"):
        namespace["test_nexthop_flap"](
            dut, helper.tbinfo, Mock(), f"CRC-DST_IP-{ip_version}-None-None", {}, None,
            None, {"ecmp": [], "lag": []}, ["CRC"], None, dut, loganalyzer, None)
    counts = [2, 1, 2] if withdraw_ready else [2, 1]
    assert readiness_calls == [(dut, helper.tbinfo, count, ip_version) for count in counts]
    assert namespace["ptf_runner"].call_count == (3 if withdraw_ready else 1)
    cli, prefix = ("ip6", "::/0") if topology == "t1-lag" and ip_version == "ipv6" else ("ip", "0.0.0.0/0")
    assert [call.args[0] for call in dut.shell.call_args_list] == [
        f"docker exec syncd vppctl show {cli} fib {prefix}" for _ in counts]
    namespace["ignore_expected_vpp_link_churn"].assert_called_once_with(
        dut, helper.tbinfo, loganalyzer, ["Ethernet0"])
    assert analyzer.ignore_regex[0] == "existing-ignore"
    assert len(analyzer.ignore_regex) == (2 if topology == "t1-lag" else 1)


@pytest.fixture
def protocol_test():
    root = Path(__file__).resolve().parents[3]
    path = root / "ansible/roles/test/files/ptftests/py3/generic_hash_test.py"
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))]
    namespace = {"BaseTest": object, "math": math, "logging": logging, "random": random, "testutils": Mock()}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    cls = namespace["GenericHashTest"]
    test = cls.__new__(cls)
    test.dataplane = SimpleNamespace(PollFailure=type("PollFailure", (), {}))
    test.ipver = "ipv4"
    test.hash_field = "IP_PROTOCOL"
    test.inner_ipver = None
    test.is_l2_test = False
    test.ecmp_hash = True
    test.lag_hash = False
    test.protocol_domain_validation = True
    test.require_all_expected_ports = False
    test.expected_port_groups = [[2 * index, 2 * index + 1] for index in range(8)]
    test.expected_port_list = sum(test.expected_port_groups, [])
    test.sending_ports = [20]
    test.src_ip_interval = SimpleNamespace(get_first_ip=lambda: "8.0.0.0")
    test.dst_ip_interval = SimpleNamespace(get_first_ip=lambda: "9.0.0.0")
    test.generate_pkt = Mock(side_effect=lambda *args: (args[4], args[4], str(args[4])))
    namespace["testutils"].verify_packet_any_port.side_effect = lambda _, protocol, ports, timeout: (
        2 * (protocol % 8), b"received")
    namespace["testutils"].dp_poll.return_value = test.dataplane.PollFailure()
    return SimpleNamespace(test=test, validate=namespace["validate_protocol_distribution"],
                           transport=namespace["testutils"])


@pytest.mark.parametrize("asic,topology", [("vpp", "t1-lag"), ("vpp", "t0"), ("mellanox", "t1-lag")])
@pytest.mark.parametrize("field", ["SRC_IP", "DST_IP", "L4_SRC_PORT", "L4_DST_PORT", "IP_PROTOCOL"])
def test_all_port_requirement_is_limited_to_target_address_port_cases(helper, asic, topology, field):
    """Enable completeness only for the target without changing entropy expectations or tolerances."""
    helper.tbinfo["topo"]["name"] = topology
    params = helper.namespace["generate_test_params"](
        SimpleNamespace(facts={"asic_type": asic, "router_mac": "00:11:22:33:44:55"}),
        helper.tbinfo, {}, field, "ipv4", "None", "None", {}, {}, True, True)
    assert params.get("require_all_expected_ports", False) == (
        asic == "vpp" and topology == "t1-lag" and field != "IP_PROTOCOL")
    assert params["balancing_range"] == 0.3 and params["balancing_test_times"] == 480


@pytest.mark.parametrize("require_all", [False, True])
@pytest.mark.parametrize("counts", [
    {port: 512 for port in range(15)},
    {**{port: 512 for port in range(15)}, 15: 0},
    {port: 480 for port in range(16)},
    {**{port: 480 for port in range(14)}, 14: 960},
])
def test_combined_balance_rejects_missing_members_without_changing_tolerance(protocol_test, counts, require_all):
    """Reject the in-tolerance synthetic missing-member map only when opted in."""
    test = protocol_test.test
    test.ecmp_hash = test.lag_hash = True
    test.require_all_expected_ports = require_all
    test.balancing_test_times = 480
    test.balancing_range = 0.3
    missing = any(counts.get(port, 0) <= 0 for port in test.expected_port_list)
    outside_tolerance = any(not 480 * 0.7 <= count <= 480 * 1.3 for count in counts.values())
    with pytest.raises(AssertionError) if (require_all and missing) or outside_tolerance else nullcontext():
        test.check_balancing(counts)


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
def test_complete_domain_is_sent_three_times_with_fixed_other_fields(protocol_test, family):
    test = protocol_test.test
    test.ipver = family
    test.require_all_expected_ports = True  # Protocol mode must not require both members even if passed this option.
    test.runTest()
    domain = test.get_ip_protocol_domain()
    protocols = [call.args[4] for call in test.generate_pkt.call_args_list]
    assert protocols == domain + list(reversed(domain)) + domain
    assert len(domain) == (248 if family == "ipv4" else 247)
    assert {call.args[:4] for call in test.generate_pkt.call_args_list} == {("8.0.0.0", "9.0.0.0", 1234, 80)}
    assert {call.args[5:] for call in test.generate_pkt.call_args_list} == {("", "")}
    assert protocol_test.transport.send_packet.call_count == 3 * len(domain)


@pytest.mark.parametrize("failure", ["loss", "unstable"])
def test_domain_runner_fails_without_retransmission(protocol_test, failure):
    test = protocol_test.test
    if failure == "loss":
        protocol_test.transport.verify_packet_any_port.side_effect = AssertionError("missing packet")
        expected_sends = 1
    else:
        domain = test.get_ip_protocol_domain()
        protocol_test.transport.verify_packet_any_port.side_effect = (
            [(0, b"received")] * len(domain) + [(2, b"received")])
        expected_sends = len(domain) + 1
    with pytest.raises(AssertionError, match="missing packet|changed receiving port"):
        test.runTest()
    assert protocol_test.transport.send_packet.call_count == expected_sends


@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
@pytest.mark.parametrize("duplicate", [None, "same_member", "other_member", "other_path", "unexpected_port"])
def test_protocol_transport_detects_duplicates_before_next_send(protocol_test, family, duplicate):
    test = protocol_test.test
    test.ipver = family
    pending = deque()

    def send(_test, _port, protocol):
        port = test.expected_port_list[2 * (protocol % 8)]
        pending.extend([(port, protocol), (test.sending_ports[0], -1)])
        if duplicate and protocol_test.transport.send_packet.call_count == 1:
            extra_port = {"same_member": port, "other_member": port + 1,
                          "other_path": (port + 2) % 16, "unexpected_port": 99}[duplicate]
            pending.append((extra_port, protocol))

    def poll(_test, device_number=0, port_number=None, timeout=None, exp_pkt=None):
        assert device_number == 0 and port_number is None
        while pending:
            port, protocol = pending.popleft()
            if protocol == exp_pkt:
                return SimpleNamespace(port=port, packet=protocol, format=lambda: f"packet on port {port}")
        return test.dataplane.PollFailure()

    def receive(_test, protocol, ports, timeout):
        result = protocol_test.transport.dp_poll(_test, exp_pkt=protocol, timeout=timeout)
        assert not isinstance(result, test.dataplane.PollFailure)
        return ports.index(result.port), b"received"

    protocol_test.transport.send_packet.side_effect = send
    protocol_test.transport.verify_packet_any_port.side_effect = receive
    protocol_test.transport.dp_poll.side_effect = poll
    with pytest.raises(AssertionError, match="duplicated") if duplicate else nullcontext():
        test.runTest()
    expected_sends = 1 if duplicate else 3 * len(test.get_ip_protocol_domain())
    assert protocol_test.transport.send_packet.call_count == expected_sends
    assert all(protocol == -1 for _, protocol in pending)


def protocol_observations(domain, groups, counts):
    return dict(zip(domain, ([group[0]] * 3 for group, count in zip(groups, counts) for _ in range(count))))


def test_finite_domain_bound_does_not_treat_repeated_packets_as_independent(protocol_test):
    test = protocol_test.test
    domain = test.get_ip_protocol_domain()
    counts = [21, 31, 34, 33, 35, 24, 39, 31]
    observations = protocol_observations(domain, test.expected_port_groups, counts)
    assert protocol_test.validate(observations, domain, test.expected_port_groups, 3) == counts
    assert min(counts) < len(domain) / 8 * 0.7  # The old fixed 30% requirement is deliberately not asserted.


@pytest.mark.parametrize("fault,message", [
    ("ignored", "every ECMP path"),
    ("missing_path", "every ECMP path"),
    ("biased", "ECMP bias"),
    ("unstable", "changed receiving port"),
    ("missing_protocol", "protocol domain"),
    ("missing_repeat", "missing repeated observations"),
    ("lag_entropy", "multiple members within a LAG"),
    ("unexpected_port", "unexpected port"),
])
def test_protocol_contract_rejects_negative_controls(protocol_test, fault, message):
    test = protocol_test.test
    domain = test.get_ip_protocol_domain()
    counts = [31] * 8
    if fault == "ignored":
        counts = [248] + [0] * 7
    elif fault == "missing_path":
        counts = [62, 0] + [31] * 6
    elif fault == "biased":
        counts = [62, 26, 26, 26, 27, 27, 27, 27]
    observations = protocol_observations(domain, test.expected_port_groups, counts)
    if fault == "unstable":
        observations[domain[0]][-1] = 2
    elif fault == "missing_protocol":
        del observations[domain[0]]
    elif fault == "missing_repeat":
        observations[domain[0]].pop()
    elif fault == "lag_entropy":
        observations[domain[0]] = [1] * 3
    elif fault == "unexpected_port":
        observations[domain[0]] = [99] * 3
    with pytest.raises(AssertionError, match=message):
        protocol_test.validate(observations, domain, test.expected_port_groups, 3)
