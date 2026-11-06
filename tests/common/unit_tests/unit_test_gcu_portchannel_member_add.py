"""Offline checks for the 400G GCU member-add baseline and restore flow."""

import ast
from contextlib import nullcontext
import logging
from pathlib import Path
import random
import re
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


SCRIPT = Path(__file__).parents[2] / "generic_config_updater/add_cluster/test_portchannel_400G_member_add.py"
HELPERS = SCRIPT.with_name("portchannel_helpers.py")


def _assert(condition, message):
    if not condition:
        pytest.fail(message)


def _load_functions(path, names, namespace):
    """Load the production functions without importing DUT-only dependencies."""
    tree = ast.parse(path.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    for node in functions:
        node.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)


@pytest.fixture
def harness():
    namespace = {
        "pytest": pytest,
        "pytest_assert": _assert,
        "logger": logging.getLogger(__name__),
        "random": random,
        "re": re,
        "allure": SimpleNamespace(step=lambda description: nullcontext()),
        "LAG_STATE_WAIT_TIME": 1,
        "LAG_STATE_WAIT_INTERVAL": 1,
        "wait_until": lambda timeout, interval, delay, predicate: predicate(),
        "_escape_json_pointer_key": lambda value: value,
        "format_sonic_interface_dict": lambda value: value,
        "_format_sonic_queue_dict": lambda value: value,
        "get_portchannel_member_value": Mock(return_value={}),
        "_saved_admin_status_expectation": Mock(return_value=(True, "up")),
    }
    for name in (
        "save_backup_test_config", "restore_backup_test_config", "config_reload",
        "_apply_patch_with_dry_run", "verify_portchannel_member_state",
        "_restore_dut_via_minigraph", "_ordered_asic_indices", "_build_dut_context",
        "get_asic_interface_status_map", "get_portchannel_status_map", "find_portchannels_by_member_speed",
        "verify_asic_db_lag_member_state", "verify_counters_db_lag_member_readable",
        "verify_acl_feature_bindings", "verify_restored_member_dataplane",
        "get_portchannel_peer_context", "set_peer_portchannel_min_links", "restore_peer_portchannel_min_links",
    ):
        namespace[name] = Mock()
    namespace["_wait_for_portchannel_up_or_log"] = Mock(return_value=True)
    namespace["_portchannel_member_state_matches"] = Mock(return_value=True)
    _load_functions(HELPERS, {"runner_member_selected"}, namespace)
    namespace["_runner_member_selected"] = namespace["runner_member_selected"]
    _load_functions(SCRIPT, {
        "_collect_portchannel_member_add_options", "_expected_portchannel_members",
        "_iter_buffer_pg_entries", "_iter_queue_entries", "_get_port_interface_entries",
        "_build_port_interface_entries", "build_portchannel_member_remove_ops",
        "build_portchannel_min_links_ops", "build_portchannel_member_add_ops",
        "verify_teamd_lag_member_state", "_reload_prepared_portchannel_config",
        "verify_post_restore_operational_state",
        "setup_portchannel_member_add", "test_portchannel_400g_member_add",
        "portchannel_peer_min_links",
    }, namespace)
    return namespace


def _runtime():
    return {
        "selected_dut_hostname": "lc0",
        "selected_asic_index": 0,
        "enum_rand_one_asic_namespace": "asic0",
        "cli_namespace_prefix": "-n asic0",
        "selected_portchannel": "PortChannel108",
        "selected_member_port": "Ethernet0",
        "remaining_member_ports": ["Ethernet8"],
        "original_min_links": "2",
        "base_min_links": 1,
        "config_facts": {"PORT": {"Ethernet0": {"admin_status": "up"}}},
    }


@pytest.mark.parametrize("minimum,member_count,eligible", [(2, 2, True), (1, 2, False), (2, 3, False), (3, 3, True)])
def test_selection_requires_an_actual_min_links_reduction(harness, minimum, member_count, eligible):
    dut = SimpleNamespace(hostname="lc0")
    context = {"asic_index": 0, "asic_namespace": "asic0", "cli_namespace_prefix": "-n asic0", "config_facts": {}}
    harness["_ordered_asic_indices"].return_value = [0]
    harness["_build_dut_context"].return_value = context
    harness["get_portchannel_status_map"].return_value = ({}, {})
    harness["find_portchannels_by_member_speed"].return_value = [{
        "portchannel": "PortChannel108",
        "members": ["Ethernet{}".format(index * 8) for index in range(member_count)],
        "original_min_links": str(minimum),
    }]
    result = harness["_collect_portchannel_member_add_options"](
        [dut], "400000", rng=SimpleNamespace(choice=lambda values: values[0]),
    )
    assert (result is not None) == eligible


@pytest.mark.parametrize("active_minimum", [1, 2])
def test_restored_lag_accepts_prepared_or_updated_active_threshold(harness, active_minimum):
    dut = Mock()
    dut.lag_facts.return_value = {"ansible_facts": {"lag_facts": {"lags": {"PortChannel108": {
        "po_intf_stat": "Up",
        "po_config": {"runner": {"min_ports": active_minimum}, "ports": {"Ethernet0": {}, "Ethernet8": {}}},
        "po_stats": {"ports": {
            member: {"runner": {"selected": True}, "link": {"up": True}}
            for member in ("Ethernet0", "Ethernet8")
        }},
    }}}}}
    harness["verify_teamd_lag_member_state"](
        dut, "PortChannel108", ["Ethernet0", "Ethernet8"], "Ethernet0", "2", alternate_min_links=1,
    )


@pytest.mark.parametrize("fault", ["wrong_threshold", "remaining_member_unselected", "extra_member", "down"])
def test_restored_lag_rejects_invalid_operational_state(harness, fault):
    lag = {
        "po_intf_stat": "Up",
        "po_config": {"runner": {"min_ports": 1}, "ports": {"Ethernet0": {}, "Ethernet8": {}}},
        "po_stats": {"ports": {member: {"runner": {"selected": True}} for member in ("Ethernet0", "Ethernet8")}},
    }
    if fault == "wrong_threshold":
        lag["po_config"]["runner"]["min_ports"] = 3
    elif fault == "remaining_member_unselected":
        lag["po_stats"]["ports"]["Ethernet8"]["runner"]["selected"] = False
    elif fault == "extra_member":
        lag["po_config"]["ports"]["Ethernet16"] = {}
    else:
        lag["po_intf_stat"] = "Down"
    dut = Mock()
    dut.lag_facts.return_value = {"ansible_facts": {"lag_facts": {"lags": {"PortChannel108": lag}}}}
    with pytest.raises(pytest.fail.Exception):
        harness["verify_teamd_lag_member_state"](
            dut, "PortChannel108", ["Ethernet0", "Ethernet8"], "Ethernet0", "2", alternate_min_links=1,
        )


def test_baseline_rejects_original_active_threshold(harness):
    dut = Mock()
    dut.lag_facts.return_value = {"ansible_facts": {"lag_facts": {"lags": {"PortChannel108": {
        "po_intf_stat": "Up",
        "po_config": {"runner": {"min_ports": 2}, "ports": {"Ethernet8": {}}},
        "po_stats": {"ports": {"Ethernet8": {"runner": {"selected": True}}}},
    }}}}}
    with pytest.raises(pytest.fail.Exception):
        harness["verify_teamd_lag_member_state"](dut, "PortChannel108", ["Ethernet8"], "Ethernet8", 1)


def test_post_restore_separates_config_and_runtime_thresholds(harness):
    dut = Mock()
    harness["verify_teamd_lag_member_state"] = Mock()
    harness["verify_post_restore_operational_state"](dut, _runtime(), None, None, None)
    harness["verify_teamd_lag_member_state"].assert_called_once_with(
        dut, "PortChannel108", ["Ethernet0", "Ethernet8"], "Ethernet0", "2", alternate_min_links=1,
    )


@pytest.mark.parametrize("failure", [None, "save", "reload"])
def test_setup_saves_and_reloads_without_file_backups(harness, failure):
    events = []
    dut = Mock(hostname="lc0")

    def save(command):
        events.append(command)
        if failure == "save":
            raise RuntimeError("save failed")

    def reload(*args, **kwargs):
        events.append("reload")
        if failure == "reload":
            pytest.fail("reload failed")

    dut.command.side_effect = save
    harness["config_reload"].side_effect = reload
    if failure:
        with pytest.raises((RuntimeError, pytest.fail.Exception)):
            harness["_reload_prepared_portchannel_config"](dut, "loganalyzer")
    else:
        harness["_reload_prepared_portchannel_config"](dut, "loganalyzer")
    assert events == (["config save -y"] if failure == "save" else ["config save -y", "reload"])
    harness["save_backup_test_config"].assert_not_called()
    harness["restore_backup_test_config"].assert_not_called()
    if failure != "save":
        harness["config_reload"].assert_called_once_with(
            dut, config_source="config_db", safe_reload=True, wait_for_bgp=True, ignore_loganalyzer="loganalyzer",
        )


@pytest.mark.parametrize("baseline_up", [True, False])
def test_setup_requires_operational_baseline_before_yield(harness, baseline_up):
    events = []
    runtime = _runtime()
    dut = Mock(hostname="lc0")
    request = SimpleNamespace(addfinalizer=Mock())
    harness["_apply_patch_with_dry_run"].side_effect = lambda *args, **kwargs: events.append("patch")
    harness["_reload_prepared_portchannel_config"] = Mock(side_effect=lambda *args: events.append("reload"))
    harness["_wait_for_portchannel_up_or_log"].return_value = baseline_up
    harness["verify_teamd_lag_member_state"] = Mock(side_effect=lambda *args, **kwargs: events.append("teamd"))
    setup = harness["setup_portchannel_member_add"](request, {"lc0": dut}, runtime, None, None, None)
    if baseline_up:
        assert next(setup) is runtime
        assert events == ["patch", "patch", "reload", "teamd"]
        harness["verify_teamd_lag_member_state"].assert_called_once_with(
            dut, "PortChannel108", ["Ethernet8"], "Ethernet8", 1,
        )
    else:
        with pytest.raises(pytest.fail.Exception):
            next(setup)
        assert "teamd" not in events
    request.addfinalizer.assert_called_once()
    setup.close()


@pytest.mark.parametrize("stage", ["passed", "setup_failed", "test_failed"])
def test_cleanup_always_restores_minigraph(harness, stage):
    dut = Mock(hostname="lc0")
    request = SimpleNamespace(addfinalizer=Mock())
    runtime = _runtime()
    harness["_reload_prepared_portchannel_config"] = Mock()
    harness["verify_teamd_lag_member_state"] = Mock()
    harness["verify_post_restore_operational_state"] = Mock()
    setup = harness["setup_portchannel_member_add"](request, {"lc0": dut}, runtime, None, None, None)
    if stage == "setup_failed":
        harness["_wait_for_portchannel_up_or_log"].return_value = False
        with pytest.raises(pytest.fail.Exception):
            next(setup)
    else:
        next(setup)
        if stage == "test_failed":
            harness["verify_post_restore_operational_state"].side_effect = pytest.fail.Exception("traffic failed")
            with pytest.raises(pytest.fail.Exception):
                harness["test_portchannel_400g_member_add"]({"lc0": dut}, runtime, None, None, None)
        else:
            harness["test_portchannel_400g_member_add"]({"lc0": dut}, runtime, None, None, None)
    patch_count = harness["_apply_patch_with_dry_run"].call_count
    request.addfinalizer.call_args.args[0]()
    harness["_restore_dut_via_minigraph"].assert_called_once_with(dut, None)
    assert harness["_apply_patch_with_dry_run"].call_count == patch_count
    setup.close()


def test_minigraph_recovery_failure_is_not_hidden(harness):
    dut = Mock(hostname="lc0")
    request = SimpleNamespace(addfinalizer=Mock())
    harness["_reload_prepared_portchannel_config"] = Mock()
    harness["verify_teamd_lag_member_state"] = Mock()
    setup = harness["setup_portchannel_member_add"](request, {"lc0": dut}, _runtime(), None, None, None)
    next(setup)
    harness["_restore_dut_via_minigraph"].side_effect = pytest.fail.Exception("recovery failed")
    with pytest.raises(pytest.fail.Exception):
        request.addfinalizer.call_args.args[0]()
    setup.close()


def test_local_fixture_prevents_later_checkpoint_restoration(tmp_path):
    tree = ast.parse(SCRIPT.read_text())
    fixture = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == "use_function_scoped_minigraph_cleanup")
    (tmp_path / "conftest.py").write_text(
        "import pytest\n\n@pytest.fixture(scope='module', autouse=True)\n" +
        "def setup_env():\n    raise AssertionError('shared checkpoint teardown must not run')\n"
    )
    test_file = tmp_path / "test_cleanup_owner.py"
    fixture_source = "\n".join(
        SCRIPT.read_text().splitlines()[fixture.decorator_list[0].lineno - 1:fixture.end_lineno]
    )
    test_file.write_text(
        "import pytest\n\n" + fixture_source +
        "\n\ndef test_cleanup_owner():\n    pass\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--confcutdir", str(tmp_path), "-o", "addopts=", "-q", str(test_file)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_member_add_restores_config_min_links_without_save_or_reload(harness):
    dut = Mock(hostname="lc0")
    runtime = _runtime()
    harness["verify_post_restore_operational_state"] = Mock()
    harness["test_portchannel_400g_member_add"]({"lc0": dut}, runtime, None, None, None)
    patch = harness["_apply_patch_with_dry_run"].call_args.args[1]
    assert {"op": "add", "path": "/asic0/PORTCHANNEL_MEMBER/PortChannel108|Ethernet0", "value": {}} in patch
    assert {"op": "add", "path": "/asic0/PORTCHANNEL/PortChannel108/min_links", "value": "2"} in patch
    dut.command.assert_not_called()
    harness["config_reload"].assert_not_called()
    harness["save_backup_test_config"].assert_not_called()


@pytest.fixture
def peer_harness(harness):
    state = {"min_links": 2}

    def read_config(**kwargs):
        lines = ["interface Port-Channel1"]
        if state["min_links"] is not None:
            lines.append("   port-channel min-links {}".format(state["min_links"]))
        return {"stdout": ["\n".join(lines)]}

    def apply_config(**kwargs):
        command = kwargs["lines"][0]
        state["min_links"] = None if command.startswith("no ") else int(command.split()[-1])
        return {"changed": True}

    peer = SimpleNamespace(
        hostname="peer", eos_command=Mock(side_effect=read_config), eos_config=Mock(side_effect=apply_config),
        get_portchannel_by_member=Mock(return_value="Port-Channel1"),
    )
    harness["EosHost"] = SimpleNamespace
    _load_functions(HELPERS, {
        "get_peer_portchannel_min_links", "get_portchannel_peer_context",
        "set_peer_portchannel_min_links", "restore_peer_portchannel_min_links",
    }, harness)
    runtime = _runtime()
    runtime["config_facts"]["DEVICE_NEIGHBOR"] = {
        "Ethernet0": {"name": "peer", "port": "Ethernet1"},
        "Ethernet8": {"name": "peer", "port": "Ethernet2"},
    }
    return harness, peer, state, runtime


@pytest.mark.parametrize("original", [None, 1, 2, 3])
def test_peer_threshold_lowering_preserves_exact_original_setting(peer_harness, original):
    harness, peer, state, runtime = peer_harness
    state["min_links"] = original
    request = SimpleNamespace(addfinalizer=Mock())
    fixture = harness["portchannel_peer_min_links"](request, runtime, {"peer": {"host": peer}})
    context = next(fixture)
    assert context["original_min_links"] == original
    assert state["min_links"] == (1 if original is not None and original > 1 else original)
    assert peer.get_portchannel_by_member.call_count == 2
    request.addfinalizer.call_args.args[0]()
    assert state["min_links"] == original
    assert peer.eos_config.call_count == (2 if original is not None and original > 1 else 0)
    fixture.close()


def test_peer_resolution_rejects_members_on_different_lags_before_mutation(peer_harness):
    harness, peer, _, runtime = peer_harness
    peer.get_portchannel_by_member.side_effect = ["Port-Channel1", "Port-Channel2"]
    with pytest.raises(pytest.fail.Exception):
        harness["get_portchannel_peer_context"](runtime, {"peer": {"host": peer}})
    peer.eos_config.assert_not_called()


def test_peer_resolution_skips_unsupported_neighbors_before_mutation(peer_harness):
    harness, peer, _, runtime = peer_harness
    with pytest.raises(pytest.skip.Exception):
        harness["get_portchannel_peer_context"](runtime, {"peer": {"host": Mock()}})
    peer.eos_config.assert_not_called()


@pytest.mark.parametrize("output", ["", "invalid command", "interface Port-Channel1\n port-channel min-links invalid"])
def test_peer_config_read_errors_do_not_masquerade_as_unset_default(peer_harness, output):
    harness, peer, _, _ = peer_harness
    peer.eos_command.side_effect = None
    peer.eos_command.return_value = {"stdout": [output]}
    with pytest.raises(pytest.fail.Exception):
        harness["get_peer_portchannel_min_links"](peer, "Port-Channel1")
    peer.eos_config.assert_not_called()


def test_peer_partial_apply_failure_has_registered_recovery(peer_harness):
    harness, peer, state, runtime = peer_harness
    request = SimpleNamespace(addfinalizer=Mock())
    original_apply = peer.eos_config.side_effect

    def partial_failure(**kwargs):
        request.addfinalizer.assert_called_once()
        original_apply(**kwargs)
        if state["min_links"] == 1:
            pytest.fail("CLI disconnected after applying config")
        return {"changed": True}

    peer.eos_config.side_effect = partial_failure
    fixture = harness["portchannel_peer_min_links"](request, runtime, {"peer": {"host": peer}})
    with pytest.raises(pytest.fail.Exception):
        next(fixture)
    assert state["min_links"] == 1
    request.addfinalizer.call_args.args[0]()
    assert state["min_links"] == 2


def test_peer_restore_failure_is_not_hidden(peer_harness):
    harness, peer, _, runtime = peer_harness
    request = SimpleNamespace(addfinalizer=Mock())
    fixture = harness["portchannel_peer_min_links"](request, runtime, {"peer": {"host": peer}})
    next(fixture)
    peer.eos_config.side_effect = RuntimeError("peer unavailable during cleanup")
    with pytest.raises(RuntimeError, match="peer unavailable"):
        request.addfinalizer.call_args.args[0]()
    fixture.close()


def test_peer_restore_can_remove_a_setting_that_was_originally_absent(peer_harness):
    harness, peer, state, _ = peer_harness
    context = {"host": peer, "name": "peer", "portchannel": "Port-Channel1",
               "original_min_links": None, "changed": True}
    harness["restore_peer_portchannel_min_links"](context)
    assert state["min_links"] is None
    peer.eos_config.assert_called_once_with(lines=["no port-channel min-links"], parents=["interface Port-Channel1"])
