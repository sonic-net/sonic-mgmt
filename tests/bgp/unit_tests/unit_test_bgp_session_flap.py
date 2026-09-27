"""Regression tests for BGP session-flap worker and mark behavior."""

import ast
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml


MODULE_PATH = Path(__file__).resolve().parents[1] / "test_bgp_session_flap.py"
MARKS_PATH = (
    Path(__file__).resolve().parents[2]
    / "common"
    / "plugins"
    / "conditional_mark"
    / "tests_mark_conditions.yaml"
)
VPP_MARKS_PATH = (
    Path(__file__).resolve().parents[2]
    / "common"
    / "plugins"
    / "conditional_mark"
    / "tests_mark_conditions_sonic_vpp.yaml"
)
HELPERS = {
    "get_bgp_session_states",
    "filter_external_bgp_sessions",
    "get_bgp_session_groups",
    "get_external_bgp_session_states",
    "all_bgp_sessions_established",
    "get_unique_neighbor_hosts",
    "restore_neighbor_bgp",
    "stop_flap_workers",
    "start_flap_worker",
    "assert_flap_workers_succeeded",
    "flap_neighbor_session",
    "test_bgp_single_session_flaps",
    "test_bgp_multiple_session_flaps",
}


def _assert(condition, message="BGP session-flap check failed"):
    assert condition, message


class CapturingThread(threading.Thread):
    """Dependency-free InterruptableThread equivalent."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._exception = None

    def run(self):
        try:
            super().run()
        except Exception:
            self._exception = sys.exc_info()

    def join(self, timeout=None, suppress_exception=False):
        super().join(timeout)
        if self._exception:
            if suppress_exception:
                return self._exception
            raise self._exception[1]


class FakeNeighbor:
    def __init__(self, hostname=None, fail_kill=False, fail_start=False):
        self.hostname = hostname or "neighbor-{}".format(id(self))
        self.fail_kill = fail_kill
        self.fail_start = fail_start
        self.kill_count = 0
        self.start_count = 0

    def kill_bgpd(self):
        self.kill_count += 1
        if self.fail_kill:
            raise RuntimeError("kill failed")
        time.sleep(0.001)

    def start_bgpd(self):
        self.start_count += 1
        if self.fail_start:
            raise RuntimeError("start failed")
        time.sleep(0.001)


@pytest.fixture
def flap_helpers():
    tree = ast.parse(MODULE_PATH.read_text())
    selected = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in HELPERS
    ]
    namespace = {
        "BGP_SESSION_TIMEOUT": 300,
        "FLAP_THREAD_STOP_TIMEOUT": 2,
        "InterruptableThread": CapturingThread,
        "cpuSpike": 10,
        "get_cpu_stats": lambda duthost: [0] * 9,
        "memSpike": 1.3,
        "pytest_assert": _assert,
        "pytest": pytest,
        "sys": sys,
        "threading": threading,
        "time": time,
        "traceback": __import__("traceback"),
        "wait_time": 2,
    }
    module = compile(
        ast.Module(body=selected, type_ignores=[]),
        str(MODULE_PATH),
        "exec"
    )
    exec(module, namespace)
    return namespace


def test_single_worker_performs_flap_and_stops_cleanly(flap_helpers):
    neighbor = FakeNeighbor()
    stop_event = threading.Event()
    worker = flap_helpers["start_flap_worker"](neighbor, stop_event)

    assert worker[1].wait(1), "worker did not complete a flap"
    errors = flap_helpers["stop_flap_workers"](
        [worker], stop_event, [neighbor]
    )
    flap_helpers["assert_flap_workers_succeeded"]([worker], errors)

    assert neighbor.kill_count >= 1
    assert neighbor.start_count >= neighbor.kill_count


def test_multiple_workers_receive_neighbor_objects(flap_helpers):
    neighbors = [FakeNeighbor(), FakeNeighbor(), FakeNeighbor()]
    stop_event = threading.Event()
    workers = [
        flap_helpers["start_flap_worker"](neighbor, stop_event)
        for neighbor in neighbors
    ]

    assert all(worker[1].wait(1) for worker in workers)
    errors = flap_helpers["stop_flap_workers"](workers, stop_event, neighbors)
    flap_helpers["assert_flap_workers_succeeded"](workers, errors)

    assert all(neighbor.kill_count >= 1 for neighbor in neighbors)


def test_neighbor_hosts_are_deduplicated_by_hostname(flap_helpers):
    first_vm = FakeNeighbor(hostname="VM0104")
    duplicate_vm = FakeNeighbor(hostname="VM0104")
    second_vm = FakeNeighbor(hostname="VM0105")

    neighbors = flap_helpers["get_unique_neighbor_hosts"]([
        first_vm, duplicate_vm, second_vm
    ])

    assert neighbors == [first_vm, second_vm]


def test_setup_selects_unique_physical_neighbor_hosts():
    tree = ast.parse(MODULE_PATH.read_text())
    setup_node = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "setup"
    )
    assignment = next(
        node for node in setup_node.body
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "neighbor_hosts"
                for target in node.targets
            )
        )
    )

    assert isinstance(assignment.value, ast.Call)
    assert assignment.value.func.id == "get_unique_neighbor_hosts"
    assert assignment.value.args[0].func.attr == "values"
    assert assignment.value.args[0].func.value.id == "tor_neighbors"

    setup_info_assignment = next(
        node for node in setup_node.body
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "setup_info"
                for target in node.targets
            )
        )
    )
    setup_info = {
        key.value: value
        for key, value in zip(
            setup_info_assignment.value.keys,
            setup_info_assignment.value.values
        )
    }
    assert setup_info["neighbors"].id == "neighbor_hosts"

    restore_assignment = next(
        node for node in setup_node.body
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "restore_errors"
                for target in node.targets
            )
        )
    )
    assert restore_assignment.value.func.id == "restore_neighbor_bgp"
    assert restore_assignment.value.args[0].id == "neighbor_hosts"


def test_multiple_session_test_passes_neighbor_objects(flap_helpers):
    neighbors = [FakeNeighbor(), FakeNeighbor()]
    received_neighbors = []
    stopped_neighbors = []

    def record_worker(neighbor, stop_event):
        received_neighbors.append(neighbor)
        completed = threading.Event()
        completed.set()
        return CapturingThread(), completed

    def record_stop(workers, stop_event, selected_neighbors):
        stopped_neighbors.extend(selected_neighbors)
        return []

    flap_helpers.update({
        "assert_flap_workers_succeeded": (
            lambda workers, errors, test_exception=None: _assert(
                not errors and test_exception is None
            )
        ),
        "get_cpu_stats": lambda duthost: [0] * 9,
        "start_flap_worker": record_worker,
        "stop_flap_workers": record_stop,
        "time": type(
            "NoWait", (), {"sleep": staticmethod(lambda seconds: None)}
        ),
    })

    flap_helpers["test_bgp_multiple_session_flaps"]({
        "duthost": object(),
        "neighbors": neighbors,
    })

    assert received_neighbors == neighbors
    assert stopped_neighbors == neighbors


def test_partial_start_reports_primary_and_worker_failures(flap_helpers):
    neighbors = [FakeNeighbor(fail_kill=True), FakeNeighbor()]
    real_start_flap_worker = flap_helpers["start_flap_worker"]
    start_count = 0

    def fail_second_worker(neighbor, stop_event):
        nonlocal start_count
        start_count += 1
        if start_count == 2:
            raise RuntimeError("second worker start failed")
        return real_start_flap_worker(neighbor, stop_event)

    flap_helpers["start_flap_worker"] = fail_second_worker

    with pytest.raises(AssertionError) as exc_info:
        flap_helpers["test_bgp_multiple_session_flaps"]({
            "duthost": object(),
            "neighbors": neighbors,
        })

    message = str(exc_info.value)
    assert "second worker start failed" in message
    assert "kill failed" in message
    assert neighbors[0].start_count == 1
    assert neighbors[1].start_count == 1


def test_worker_exception_fails_after_neighbor_restore(flap_helpers):
    neighbor = FakeNeighbor(fail_kill=True)
    stop_event = threading.Event()
    worker = flap_helpers["start_flap_worker"](neighbor, stop_event)
    worker[0].join(timeout=1, suppress_exception=True)

    errors = flap_helpers["stop_flap_workers"](
        [worker], stop_event, [neighbor]
    )

    assert neighbor.start_count == 1
    with pytest.raises(AssertionError, match="kill failed"):
        flap_helpers["assert_flap_workers_succeeded"]([worker], errors)


def test_restore_attempts_every_neighbor_and_reports_failures(flap_helpers):
    failing_neighbor = FakeNeighbor(fail_start=True)
    healthy_neighbor = FakeNeighbor()

    errors = flap_helpers["restore_neighbor_bgp"](
        [failing_neighbor, healthy_neighbor]
    )

    assert failing_neighbor.start_count == 1
    assert healthy_neighbor.start_count == 1
    assert len(errors) == 1
    assert "start failed" in errors[0]


def test_session_groups_flap_external_and_recover_all_peers(flap_helpers):
    class FakeDut:
        def bgp_facts(self, instance_id):
            assert instance_id == 0
            return {
                "ansible_facts": {
                    "bgp_neighbors": {
                        "10.0.0.1": {
                            "description": "ARISTA01T0",
                            "peer group": "EXTERNAL",
                            "state": "established",
                        },
                        "10.0.0.2": {
                            "description": "ASIC0",
                            "peer group": "INTERNAL",
                            "state": "idle",
                        },
                        "10.0.0.3": {
                            "description": "CHASSIS_PEER",
                            "peer group": "VOQ_CHASSIS",
                            "state": "established",
                        },
                    }
                }
            }

    duthost = FakeDut()
    all_sessions, external_sessions, recovery_neighbor_ips = (
        flap_helpers["get_bgp_session_groups"](duthost, 0, [])
    )

    assert list(all_sessions) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert list(external_sessions) == ["10.0.0.1"]
    assert recovery_neighbor_ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert flap_helpers["all_bgp_sessions_established"](
        duthost, 0, ["10.0.0.1"]
    )
    assert not flap_helpers["all_bgp_sessions_established"](
        duthost, 0, recovery_neighbor_ips
    )


def test_max_route_xfail_has_explicit_conditions():
    marks = yaml.safe_load(MARKS_PATH.read_text())
    xfail = marks[
        "bgp/test_bgp_max_route.py::test_bgp_max_prefix_behavior"
    ]["xfail"]

    assert xfail["conditions_logical_operator"] == "and"
    assert xfail["conditions"] == [
        "is_multi_asic==True",
        "asic_type in ['vs']",
        "https://github.com/sonic-net/sonic-mgmt/issues/21691",
    ]


def test_vpp_session_xfail_remains_while_issue_is_open():
    marks = yaml.safe_load(VPP_MARKS_PATH.read_text())
    xfail = marks[
        "bgp/test_bgp_session.py::test_bgp_session_interface_down"
    ]["xfail"]

    assert xfail["conditions"] == [
        "https://github.com/sonic-net/sonic-mgmt/issues/27487 "
        "and asic_type in ['vpp']"
    ]
