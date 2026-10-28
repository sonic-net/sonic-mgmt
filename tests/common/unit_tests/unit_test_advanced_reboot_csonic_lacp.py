import ast
import argparse
import re
import shlex
from collections import defaultdict
from operator import itemgetter
from pathlib import Path

import pytest


PTF_DIR = Path(__file__).parents[2] / "ptftests" / "py3"
SCRIPT = PTF_DIR / "advanced-reboot.py"
SONIC_SCRIPT = PTF_DIR / "sonic.py"
CONFTEST = Path(__file__).parents[2] / "conftest.py"
ADVANCED_REBOOT_FIXTURE = Path(__file__).parents[1] / "fixtures" / "advanced_reboot.py"


class FakeNeighbor:
    def __init__(self, bonds="PortChannel1-bond\nPortChannel2-bond\n", mismatch=False):
        self.bonds = bonds
        self.mismatch = mismatch
        self.calls = []
        self.disconnected = False

    def connect(self):
        self.calls.append("connect")

    def disconnect(self):
        self.disconnected = True
        self.calls.append("disconnect")

    def do_cmd(self, command):
        self.calls.append(command)
        if "find Port lacp=active" in command:
            return self.bonds
        if "pgrep -x teamd" in command:
            return "" if self.bonds else "123\n"
        if "supervisorctl status teammgrd" in command:
            return "" if self.bonds else "teammgrd RUNNING\n"
        if " get Port " in " {} ".format(command):
            return '3\n' if self.mismatch else '180\n'
        return ""


class UnknownBackendNeighbor(FakeNeighbor):
    def do_cmd(self, command):
        self.calls.append(command)
        return ""


def load_method(neighbor, ssh_targets=None):
    tree = ast.parse(SCRIPT.read_text())
    reload_test = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ReloadTest"
    )
    method_names = {
        "_get_neighbor_handle",
        "_detect_csonic_lag_backend",
        "csonic_set_lacp_all_neighs",
    }
    methods = [
        node for node in reload_test.body
        if isinstance(node, ast.FunctionDef) and node.name in method_names
    ]

    class HostDevice:
        calls = []

        @staticmethod
        def getHostDeviceInstance(*args, **kwargs):
            HostDevice.calls.append((args, kwargs))
            if isinstance(neighbor, dict):
                return neighbor[args[1]]
            return neighbor

    namespace = {"HostDevice": HostDevice, "shlex": shlex}
    test_class = ast.ClassDef(
        name="Harness",
        bases=[],
        keywords=[],
        body=methods,
        decorator_list=[],
    )
    ast.fix_missing_locations(test_class)
    exec(compile(ast.Module(body=[test_class], type_ignores=[]), str(SCRIPT), "exec"), namespace)
    harness = namespace["Harness"]()
    harness.ssh_targets = ssh_targets or ["10.0.0.1"]
    harness.test_params = {
        "neighbor_type": "sonic",
        "csonic_neighbor": True,
        "csonic_neighbor_login": "configured-admin",
        "csonic_neighbor_password": "configured-password",
        "csonic_neighbor_lacp_multiplier": 3,
        "csonic_lag_backend": "unknown",
    }
    harness.host_device_calls = HostDevice.calls
    harness.csonic_neighbor_login = "configured-admin"
    harness.csonic_neighbor_password = "configured-password"
    harness.logs = []
    harness.log = harness.logs.append
    return harness


def test_sets_and_verifies_every_active_ovs_bond():
    neighbor = FakeNeighbor()
    harness = load_method(neighbor)
    harness.csonic_set_lacp_all_neighs(180)

    sets = [call for call in neighbor.calls if " set Port " in " {} ".format(call)]
    gets = [call for call in neighbor.calls if " get Port " in " {} ".format(call)]
    assert sets == [
        "sudo ovs-vsctl set Port PortChannel1-bond other_config:lacp-rx-multiplier=180",
        "sudo ovs-vsctl set Port PortChannel2-bond other_config:lacp-rx-multiplier=180",
    ]
    assert len(gets) == 2
    assert neighbor.disconnected
    assert harness.logs == [
        "cSONiC LACP receive multiplier update started: requested=180",
        "cSONiC LACP receive multiplier verified: neighbor=10.0.0.1 bond=PortChannel1-bond requested=180 actual=180",
        "cSONiC LACP receive multiplier verified: neighbor=10.0.0.1 bond=PortChannel2-bond requested=180 actual=180",
        "cSONiC LACP receive multiplier update completed: requested=180",
    ]
    _, kwargs = harness.host_device_calls[-1]
    assert kwargs["login"] == "configured-admin"
    assert kwargs["password"] == "configured-password"
    assert kwargs["connect_timeout"] == 15


def load_sonic_method(method_name):
    tree = ast.parse(SONIC_SCRIPT.read_text())
    sonic_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Sonic"
    )
    method = next(
        node for node in sonic_class.body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
    )
    namespace = {"defaultdict": defaultdict, "itemgetter": itemgetter, "re": re}
    test_class = ast.ClassDef(
        name="Harness",
        bases=[],
        keywords=[],
        body=[method],
        decorator_list=[],
    )
    ast.fix_missing_locations(test_class)
    exec(compile(ast.Module(body=[test_class], type_ignores=[]), str(SONIC_SCRIPT), "exec"), namespace)
    harness = namespace["Harness"]()
    harness.reboot_type = "warm-reboot"
    harness.bgp_v4_v6_time_diff = 40
    return harness


def test_sonic_log_parser_tolerates_missing_teamd_stream_for_userspace_ovs():
    result = load_sonic_method("parse_logs").parse_logs({})

    assert result["PortChannel was down (seconds)"] == 0
    assert result["route_timeout"] == {}


def test_sonic_ovs_lacp_parser_requires_every_bond_negotiated():
    harness = load_sonic_method("parse_lacp")
    harness.csonic_lag_backend = "userspace_ovs"

    assert harness.parse_lacp(
        "status: active negotiated\nmember: eth1: current attached\n"
        "status: active negotiated\nmember: eth2: current attached\n")
    assert not harness.parse_lacp(
        "status: active negotiated\nmember: eth1: expired detached\n")
    assert not harness.parse_lacp(
        "status: active defaulted\nmember: eth1: current attached\n")
    assert not harness.parse_lacp("")


def test_sonic_ovs_status_series_reports_interruption():
    harness = load_sonic_method("check_ovs_lacp_series_status")
    harness.fails = set()
    harness.info = set()
    data = {
        1.0: {"lacp": True},
        2.0: {"lacp": False},
        5.0: {"lacp": True},
    }

    assert harness.check_ovs_lacp_series_status(data) == (1, 3.0)


def test_sonic_ovs_status_series_reports_unrecovered_downtime():
    harness = load_sonic_method("check_ovs_lacp_series_status")
    harness.fails = set()
    harness.info = set()
    data = {
        1.0: {"lacp": True},
        2.0: {"lacp": False},
        5.0: {"lacp": False},
    }

    assert harness.check_ovs_lacp_series_status(data) == (1, 3.0)
    assert "OVS LACP session must be up when the test stops" in harness.fails


def test_fails_when_no_active_ovs_bonds_exist():
    neighbor = FakeNeighbor(bonds="")
    with pytest.raises(RuntimeError, match="No active userspace OVS LACP bonds"):
        load_method(neighbor).csonic_set_lacp_all_neighs(180)
    assert neighbor.disconnected


def test_fails_when_readback_does_not_match():
    neighbor = FakeNeighbor(mismatch=True)
    with pytest.raises(RuntimeError, match="Failed to set LACP receive multiplier"):
        load_method(neighbor).csonic_set_lacp_all_neighs(180)
    assert neighbor.disconnected


def test_cleanup_attempts_every_csonic_neighbor():
    neighbors = {
        "10.0.0.1": FakeNeighbor(bonds=""),
        "10.0.0.2": FakeNeighbor(),
    }
    harness = load_method(neighbors, ssh_targets=list(neighbors))

    with pytest.raises(RuntimeError, match="10.0.0.1"):
        harness.csonic_set_lacp_all_neighs(180, continue_on_error=True)

    assert neighbors["10.0.0.1"].disconnected
    assert neighbors["10.0.0.2"].disconnected
    assert any("PortChannel1-bond" in call for call in neighbors["10.0.0.2"].calls)


def test_detects_deployed_userspace_ovs_backend():
    harness = load_method(FakeNeighbor())

    assert harness._detect_csonic_lag_backend() == "userspace_ovs"
    assert harness.test_params["csonic_lag_backend"] == "userspace_ovs"


def test_rejects_multiplier_when_deployed_backend_is_teamd():
    harness = load_method(FakeNeighbor(bonds=""))
    harness.test_params["csonic_neighbor_lacp_multiplier"] = 180

    with pytest.raises(RuntimeError, match="requires the userspace_ovs backend"):
        harness._detect_csonic_lag_backend()


def test_rejects_unknown_deployed_backend():
    harness = load_method(UnknownBackendNeighbor())

    with pytest.raises(RuntimeError, match="Inconsistent or unknown cSONiC LAG backends.*unknown"):
        harness._detect_csonic_lag_backend()


def test_rejects_inconsistent_deployed_backends():
    neighbors = {
        "10.0.0.1": FakeNeighbor(),
        "10.0.0.2": FakeNeighbor(bonds=""),
    }
    harness = load_method(neighbors, ssh_targets=list(neighbors))

    with pytest.raises(RuntimeError, match="Inconsistent or unknown cSONiC LAG backends"):
        harness._detect_csonic_lag_backend()


def load_function(path, name, namespace=None):
    tree = ast.parse(path.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    loaded = dict(namespace or {})
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), loaded)
    return loaded[name]


def test_csonic_credentials_use_non_logged_file_transport():
    source = ADVANCED_REBOOT_FIXTURE.read_text()

    assert 'params["csonic_neighbor_credentials_file"]' in source
    assert '"csonic_neighbor_password"' not in source
    assert "mode='0600'" in source


def test_csonic_multiplier_range_validation():
    parse_multiplier = load_function(
        CONFTEST, "_csonic_lacp_multiplier", {"argparse": argparse})

    assert parse_multiplier("1") == 1
    assert parse_multiplier("3") == 3
    assert parse_multiplier("255") == 255
    for invalid in ("-1", "0", "256", "300", "not-an-integer"):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_multiplier(invalid)


def test_consecutive_lacp_gap_is_calculated_per_member():
    max_gap = load_function(SCRIPT, "get_max_lacp_packet_gap")

    assert max_gap({
        "lacp_by_member": {
            "1": [1.0, 2.0, 3.0, 8.0],
            "2": [1.5, 5.5, 6.5, 9.0],
        },
        "reboot_boundary": 7.0,
        "capture_end": 10.0,
    }) == 5.0


def test_lacp_gap_requires_post_reboot_packet_from_every_member():
    max_gap = load_function(SCRIPT, "get_max_lacp_packet_gap")

    assert max_gap({
        "lacp_by_member": {
            "1": [1.0, 2.0, 8.0],
            "2": [1.5, 5.5, 6.5],
        },
        "reboot_boundary": 7.0,
        "capture_end": 10.0,
    }) is None


def test_lacp_gap_accounts_for_trailing_silence():
    max_gap = load_function(SCRIPT, "get_max_lacp_packet_gap")

    assert max_gap({
        "lacp_by_member": {"1": [1.0, 2.0, 8.0]},
        "reboot_boundary": 7.0,
        "capture_end": 15.0,
    }) == 7.0


def test_csonic_lacp_timing_is_backend_specific():
    max_wait = load_function(SCRIPT, "get_max_allowed_lacp_session_wait")
    common = {
        "csonic_neighbor": True,
        "neighbor_type": "sonic",
        "csonic_neighbor_lacp_multiplier": 180,
    }

    assert max_wait(dict(common, csonic_lag_backend="userspace_ovs")) == 180
    assert max_wait(dict(common, csonic_lag_backend="teamd")) == 150


def load_reload_method(method_name):
    tree = ast.parse(SCRIPT.read_text())
    reload_test = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ReloadTest"
    )
    method = next(
        node for node in reload_test.body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
    )
    namespace = {}
    test_class = ast.ClassDef(
        name="Harness",
        bases=[],
        keywords=[],
        body=[method],
        decorator_list=[],
    )
    ast.fix_missing_locations(test_class)
    exec(compile(ast.Module(body=[test_class], type_ignores=[]), str(SCRIPT), "exec"), namespace)
    return namespace["Harness"]()


def make_run_test_harness(backend):
    harness = load_reload_method("runTest")
    harness.bgp_service_restart = False
    harness.reboot_type = "warm-reboot"
    harness.test_params = {
        "neighbor_type": "sonic",
        "ceos_neighbor_lacp_multiplier": 3,
        "csonic_neighbor": True,
        "csonic_neighbor_login": "admin",
        "csonic_neighbor_password": "password",
        "csonic_lag_backend": backend,
        "csonic_neighbor_lacp_multiplier": 180,
    }
    harness.fails = {"dut": set()}
    updates = []
    harness._verify_neighbors_reachable = lambda: None
    harness._detect_csonic_lag_backend = lambda: backend
    harness.ceos_set_lacp_all_neighs = lambda multiplier: None
    harness.csonic_set_lacp_all_neighs = (
        lambda multiplier, continue_on_error=False: updates.append((multiplier, continue_on_error)))

    def fail_setup():
        raise RuntimeError("setup failed")

    harness.pre_reboot_test_setup = fail_setup
    return harness, updates


def test_setup_failure_restores_csonic_multiplier():
    harness, updates = make_run_test_harness("userspace_ovs")

    with pytest.raises(RuntimeError, match="setup failed"):
        harness.runTest()

    assert updates == [(180, False), (3, True)]


def test_teamd_backend_does_not_update_ovs_multiplier():
    harness, updates = make_run_test_harness("teamd")

    with pytest.raises(RuntimeError, match="setup failed"):
        harness.runTest()

    assert updates == []
