"""Regression tests for maintenance reload prerequisites and cleanup."""

import ast
import contextlib
import json
from pathlib import Path
import posixpath
import shutil
import subprocess
import sys
from unittest.mock import Mock

import pytest


@pytest.fixture
def exercise_reload(tmp_path):
    source = tmp_path / "golden.json"
    original = {
        "BGP_DEVICE_GLOBAL": {
            "CONFED": {"asn": "64512", "peers": "64513;64514"},
            "STATE": {"tsa_enabled": "false", "wcmp_enabled": "false"},
        },
    }
    original_text = json.dumps(original)
    source.write_text(original_text)
    temporary = tmp_path / "maintenance.json"
    persistent = tmp_path / "config_db.json"
    persistent.write_text(original_text)
    backup = tmp_path / "config_db.backup.json"
    dut = Mock()
    dut.maintenance = False
    dut.dut_basic_facts.return_value = {"ansible_facts": {"dut_basic_facts": {"is_smartswitch": False}}}
    dut.tempfile.return_value = {"path": str(temporary)}
    dut.copy.side_effect = lambda src, dest, **kwargs: shutil.copyfile(src, dest)
    dut.file.side_effect = lambda path, **kwargs: Path(path).unlink()

    def command(argv, **kwargs):
        subprocess.run([sys.executable, *argv[1:]], check=True, capture_output=True, text=True)

    def shell(command):
        if command == "TSB":
            dut.maintenance = False
        elif command == "cp /etc/sonic/config_db.json /host/config_db.json.before_test_function":
            shutil.copyfile(persistent, backup)
        elif command == "mv /host/config_db.json.before_test_function /etc/sonic/config_db.json":
            shutil.move(backup, persistent)
        elif command == "sudo config save -y":
            persistent.write_text(json.dumps({"BGP_MONITORS": {"192.0.2.1": {}}}))

    dut.command.side_effect = command
    dut.shell.side_effect = shell

    def exercise(topology, fail_reload=False, monitor_established=True, routes_restored=True):
        reloads = []
        dut.check_bgp_session_state.return_value = monitor_established

        def reload(host, **kwargs):
            golden_path = kwargs.get("golden_config_path")
            golden = json.loads(Path(golden_path).read_text()) if golden_path else None
            reloads.append((kwargs, golden))
            dut.maintenance = True
            if fail_reload:
                raise RuntimeError("reload failed")

        namespace = {
            "contextlib": contextlib,
            "posixpath": posixpath,
            "pytest": pytest,
            "logger": Mock(),
            "pytest_assert": lambda condition, message: condition or pytest.fail(message),
            "wait_until": lambda timeout, interval, delay, function, *args: function(*args),
            "get_traffic_shift_state": lambda *args: "maintenance" if dut.maintenance else "normal",
            "TS_NORMAL": "normal",
            "TS_MAINTENANCE": "maintenance",
            "check_tsa_persistence_support": lambda host: True,
            "is_ipv6_only_topology": lambda tbinfo: False,
            "parse_routes_on_neighbors": lambda *args: {},
            "config_reload": reload,
            "DEFAULT_GOLDEN_CONFIG_PATH": str(source),
            "BGPMON_CONFIG_FILE": "/tmp/bgpmon.json",
            "get_routes_not_announced_to_bgpmon": lambda *args: [],
            "assert_only_loopback_routes_announced_to_neighs": Mock(),
            "assert_only_loopback_routes_in_dut_advertised_routes": Mock(),
            "verify_current_routes_announced_to_neighs": lambda *args: routes_restored,
            "check_and_log_routes_diff": lambda *args: routes_restored,
        }
        path = Path(__file__).resolve().parents[1] / "test_traffic_shift.py"
        tree = ast.parse(path.read_text())
        functions = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in (
                "_temporary_maintenance_golden", "restore_traffic_shift_config_db",
                "test_load_minigraph_with_traffic_shift_away"
            ):
                if node.name.startswith("test_"):
                    node.decorator_list = []
                functions.append(node)
        helper_path = path.parents[1] / "common" / "fixtures" / "duthost_utils.py"
        functions[:0] = [
            node for node in ast.parse(helper_path.read_text()).body
            if isinstance(node, ast.FunctionDef) and node.name == "_backup_and_restore_config_db"
        ]
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)

        def run():
            restore = namespace["restore_traffic_shift_config_db"].__wrapped__(
                {"dut": dut}, "dut", {"topo": {"type": topology}}
            )
            next(restore)
            try:
                namespace["test_load_minigraph_with_traffic_shift_away"](
                    {"dut": dut}, "dut", object(), {}, {}, {
                        "namespace": None, "local_intf": "Ethernet0",
                        "local_addr": "192.0.2.0/31", "neighbor_addr": "192.0.2.1/31",
                    },
                    "64512:1", {"topo": {"type": topology}}, None,
                )
            finally:
                with pytest.raises(StopIteration):
                    next(restore)
                if topology == "lt2":
                    assert persistent.read_text() == original_text
                    assert not backup.exists()

        if fail_reload:
            with pytest.raises(RuntimeError, match="reload failed"):
                run()
        else:
            run()
        assert source.read_text() == original_text
        return reloads

    return exercise, dut, temporary, original


@pytest.mark.parametrize("topology", ["lt2", "uma", "lma"])
def test_minigraph_reload_preserves_golden_confederation(exercise_reload, topology):
    exercise, dut, temporary, original = exercise_reload
    reloads = exercise(topology)
    kwargs, golden = reloads[0]

    assert kwargs["override_config"] is True
    assert kwargs["traffic_shift_away"] is True
    assert golden["BGP_DEVICE_GLOBAL"]["CONFED"] == original["BGP_DEVICE_GLOBAL"]["CONFED"]
    assert golden["BGP_DEVICE_GLOBAL"]["STATE"] == {"tsa_enabled": "true", "wcmp_enabled": "false"}
    assert not temporary.exists()


def test_lt2_reload_failure_cleans_temporary_golden(exercise_reload):
    exercise, dut, temporary, original = exercise_reload
    reloads = exercise("lt2", fail_reload=True)

    assert reloads[0][0]["override_config"] is True
    assert reloads[0][1]["BGP_DEVICE_GLOBAL"]["CONFED"] == original["BGP_DEVICE_GLOBAL"]["CONFED"]
    assert not temporary.exists()
    assert dut.maintenance is False


def test_ordinary_topology_keeps_minigraph_reload_behavior(exercise_reload):
    exercise, dut, temporary, original = exercise_reload
    reloads = exercise("t1")

    assert reloads[0][0]["override_config"] is False
    assert "golden_config_path" not in reloads[0][0]
    dut.tempfile.assert_not_called()
    dut.asic_instance_from_namespace.assert_not_called()


def test_lt2_reload_restores_monitor_fixture(exercise_reload):
    exercise, dut, temporary, original = exercise_reload
    exercise("lt2")

    dut.asic_instance_from_namespace.assert_called_once_with(None)
    asichost = dut.asic_instance_from_namespace.return_value
    asichost.config_ip_intf.assert_called_once_with("Ethernet0", "192.0.2.0/31", "add")
    asichost.write_to_config_db.assert_called_once_with("/tmp/bgpmon.json")
    dut.check_bgp_session_state.assert_called_once_with(["192.0.2.1"])


def test_lt2_monitor_recovery_failure_still_restores_normal_state(exercise_reload):
    exercise, dut, temporary, original = exercise_reload
    with pytest.raises(pytest.fail.Exception, match="BGP monitor session did not recover"):
        exercise("lt2", monitor_established=False)

    assert dut.maintenance is False
    assert not temporary.exists()


def test_lt2_route_recovery_failure_still_restores_persistent_config(exercise_reload):
    exercise, dut, temporary, original = exercise_reload
    with pytest.raises(pytest.fail.Exception, match="Not all ipv4 routes are announced"):
        exercise("lt2", routes_restored=False)

    assert dut.maintenance is False
    assert not temporary.exists()
