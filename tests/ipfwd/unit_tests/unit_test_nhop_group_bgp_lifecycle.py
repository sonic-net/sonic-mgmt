"""Focused tests for nexthop-group BGP lifecycle around real link flaps."""

import ast
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "test_nhop_group.py"


def _load_helper(is_vs, events):
    tree = ast.parse(MODULE_PATH.read_text())
    helper = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "bgp_stopped_for_nhop_link_flap"
    )

    def fanout_lookup(_fanouts, _hostname, _port):
        events.append("lookup")
        return "fanout", "Ethernet1"

    def toggle(_dut, _port, _fanout, _fanout_port):
        events.append("toggle")

    def wait_until(_timeout, _interval, _delay, check, neighbors):
        events.append("wait")
        return check(neighbors)

    namespace = {
        "contextmanager": contextmanager,
        "is_vs_device": lambda _dut: is_vs,
        "fanout_switch_port_lookup": fanout_lookup,
        "toggle_one_link": toggle,
        "wait_until": wait_until,
        "pytest_assert": lambda condition, message: condition or pytest.fail(message),
        "logger": Mock(),
        "time": SimpleNamespace(sleep=lambda _seconds: events.append("sleep")),
    }
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["bgp_stopped_for_nhop_link_flap"]


class FakeAsic:
    def __init__(self, events):
        self.events = events

    def stop_service(self, service):
        assert service == "bgp"
        self.events.append("stop")

    def start_service(self, service):
        assert service == "bgp"
        self.events.append("start")


class FakeDut:
    hostname = "dut"

    def __init__(self, events):
        self.events = events

    def config_facts(self, **kwargs):
        assert kwargs == {"host": "dut", "source": "running"}
        self.events.append("config")
        return {"ansible_facts": {"BGP_NEIGHBOR": {"10.0.0.1": {}}}}

    def check_bgp_session_state(self, neighbors):
        assert list(neighbors) == ["10.0.0.1"]
        return True


def test_vs_skips_all_bgp_and_fanout_lifecycle():
    events = []
    helper = _load_helper(True, events)
    with helper(FakeDut(events), FakeAsic(events), {"src_port": ["Ethernet0"]}, {}) as flapped:
        assert flapped is False
        events.append("body")

    assert events == ["body"]


def test_physical_path_stops_toggles_and_restores_once():
    events = []
    helper = _load_helper(False, events)
    with helper(FakeDut(events), FakeAsic(events), {"src_port": ["Ethernet0"]}, {}) as flapped:
        assert flapped is True
        events.append("body")

    assert events == [
        "lookup", "stop", "sleep", "toggle", "sleep", "body",
        "start", "config", "wait",
    ]


def test_exception_after_stop_still_restores_bgp_once():
    events = []
    helper = _load_helper(False, events)
    with pytest.raises(RuntimeError, match="traffic failed"):
        with helper(FakeDut(events), FakeAsic(events), {"src_port": ["Ethernet0"]}, {}):
            events.append("body")
            raise RuntimeError("traffic failed")

    assert events.count("stop") == 1
    assert events.count("start") == 1
    assert events[-3:] == ["start", "config", "wait"]
