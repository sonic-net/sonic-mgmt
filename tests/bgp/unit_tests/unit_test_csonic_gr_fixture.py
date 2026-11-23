"""Regressions for target-only shared-runtime handling in the BGP GR fixture."""

import ast
import copy
import json
import logging
import tempfile
from collections.abc import Mapping
from pathlib import Path

import pytest


pytestmark = [pytest.mark.topology("any")]

MODULE_PATH = Path(__file__).resolve().parents[1] / "conftest.py"
HELPERS = {
    "check_results",
    "_is_converged_csonic_t1_lag_neighbor",
    "_checked_csonic_gr_result",
    "_configure_csonic_t1_lag_gr",
    "_csonic_t1_lag_gr_vrfs_ready",
    "_run_csonic_t1_lag_gr_group",
}

T1_LAG = {
    "topo": {
        "name": "t1-lag",
        "properties": {"topo_is_multi_vrf": True},
    },
}
T0 = {
    "topo": {
        "name": "t0",
        "properties": {"topo_is_multi_vrf": True},
    },
}


class FakeCsonicHost:
    def __init__(self, container_name, vrf=None):
        self.container_name = container_name
        self.bgp_vrf = vrf
        self.hostname = (
            "{}:{}".format(container_name, vrf) if vrf else container_name
        )
        self.start_count = 0
        self.config_results = []
        self.clear_results = []
        self.config_calls = []
        self.command_calls = []
        self.ready_vrfs = {vrf} if vrf else set()

    def config(self, **kwargs):
        self.config_calls.append(kwargs)
        if self.config_results:
            return self.config_results.pop(0)
        return {"failed": False, "rc": 0}

    def command(self, command, **kwargs):
        self.command_calls.append((command, kwargs))
        if "summary json" in command:
            vrf = command.split("show bgp vrf ", 1)[1].split()[0]
            if vrf in self.ready_vrfs:
                return {
                    "failed": False,
                    "rc": 0,
                    "stdout": json.dumps({"ipv4Unicast": {}}),
                }
            return {"failed": False, "rc": 1, "stdout": ""}
        if self.clear_results:
            return self.clear_results.pop(0)
        return {"failed": False, "rc": 0}

    def start_bgpd(self):
        self.start_count += 1
        return {"failed": False, "rc": 0}


class FakeSonicHost(FakeCsonicHost):
    pass


class FakeEosHost:
    def __init__(self):
        self.hostname = "VM0100"
        self.eos_configs = []

    def eos_config(self, src, **kwargs):
        self.eos_configs.append((Path(src).read_text(), kwargs))
        return {"failed": False}


class FakeDut:
    hostname = "dut"

    def config_facts(self, **kwargs):
        return {"ansible_facts": {"BGP_NEIGHBOR": {}}}

    def check_bgp_session_state(self, _neighbors):
        return True

    def check_bgp_default_route(self, **kwargs):
        return True


class FakeAssert:
    def __call__(self, condition, message="assertion failed"):
        assert condition, message


def _wait_until(_timeout, _interval, _delay, function, *args, **kwargs):
    return function(*args, **kwargs)


def _parallel_run(function, _args, _kwargs, nodes, **_options):
    results = {}
    for node in nodes:
        function(node=node, results=results)
    return results


def _namespace():
    return {
        "CsonicHost": FakeCsonicHost,
        "EosHost": FakeEosHost,
        "SonicHost": FakeSonicHost,
        "Mapping": Mapping,
        "json": json,
        "logger": logging.getLogger(__name__),
        "parallel_run": _parallel_run,
        "pt_assert": FakeAssert(),
        "pytest": pytest,
        "reset_ansible_local_tmp": lambda function: function,
        "tempfile": tempfile,
        "wait_until": _wait_until,
        "is_ipv6_only_topology": lambda _tbinfo: False,
    }


def _load(include_fixture=False):
    tree = ast.parse(MODULE_PATH.read_text())
    selected = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in HELPERS:
            selected.append(copy.deepcopy(node))
        elif (
            include_fixture
            and isinstance(node, ast.FunctionDef)
            and node.name == "setup_bgp_graceful_restart"
        ):
            fixture = copy.deepcopy(node)
            fixture.decorator_list = []
            selected.append(fixture)
    namespace = _namespace()
    exec(compile(
        ast.Module(body=selected, type_ignores=[]),
        str(MODULE_PATH),
        "exec",
    ), namespace)
    return namespace


def _peer(host, name="ARISTA01T2"):
    return {
        "host": host,
        "conf": {
            "bgp": {
                "asn": 64601,
                "peers": {65100: ["10.0.0.1", "fc00::1"]},
            },
        },
        "is_multi_vrf_peer": bool(host.bgp_vrf),
        "multi_vrf_data": {
            "vrf": host.bgp_vrf,
            "primary_host": "PRIMARY",
            "primary_host_asn": 64600,
        },
        "name": name,
    }


def test_target_predicate_excludes_ordinary_csonic_t0_and_ceos():
    helpers = _load()
    converged = _peer(FakeCsonicHost("prime", "VrfARISTA01T2"))
    ordinary = _peer(FakeCsonicHost("ordinary"))
    eos = {
        "host": FakeEosHost(),
        "is_multi_vrf_peer": True,
        "multi_vrf_data": {"vrf": "ARISTA01T2"},
    }

    predicate = helpers["_is_converged_csonic_t1_lag_neighbor"]
    assert predicate(converged, T1_LAG)
    assert not predicate(converged, T0)
    assert not predicate(ordinary, T1_LAG)
    assert not predicate(eos, T1_LAG)


def test_configure_validates_nonzero_rc_failed_and_clear_results():
    helpers = _load()
    host = FakeCsonicHost("prime", "VrfARISTA01T2")
    host.config_results = [
        {"failed": False, "rc": 0},
        {"failed": True, "rc": 0, "stderr": "neighbor rejected"},
        {"failed": False, "rc": 7, "stderr": "vtysh failed"},
    ]
    host.clear_results = [
        {"failed": False, "rc": 0},
        {"failed": False, "rc": 9, "stderr": "clear failed"},
    ]

    results = helpers["_configure_csonic_t1_lag_gr"](
        _peer(host), enable=True)

    assert len(results) == 5
    assert [result.get("failed", False) for result in results] == [
        False, True, True, False, True,
    ]
    assert [call[0] for call in host.command_calls] == [
        "sudo vtysh -c 'clear bgp ipv4 *'",
        "sudo vtysh -c 'clear bgp ipv6 *'",
    ]


def test_shared_group_starts_once_waits_for_every_vrf_then_cleans_serially():
    helpers = _load()
    first = FakeCsonicHost("prime", "VrfARISTA01T2")
    second = FakeCsonicHost("prime", "VrfARISTA03T2")
    first.ready_vrfs = {"VrfARISTA01T2"}
    second.ready_vrfs = {"VrfARISTA03T2"}
    node = {
        "host": first,
        "csonic_t1_lag_peers": [
            {"host": first, "name": "ARISTA01T2"},
            {"host": second, "name": "ARISTA03T2"},
        ],
    }
    observed = []

    def operation(peer):
        observed.append(peer["name"])
        return [{"failed": False, "peer": peer["name"]}]

    results = helpers["_run_csonic_t1_lag_gr_group"](
        node, operation, start_bgpd=True)

    assert first.start_count == 1
    assert second.start_count == 0
    assert observed == ["ARISTA01T2", "ARISTA03T2"]
    assert "VrfARISTA01T2" in first.command_calls[0][0]
    assert "VrfARISTA03T2" in second.command_calls[0][0]
    assert not [result for result in results if result.get("failed", False)]


def test_shared_group_does_not_clean_before_every_vrf_is_ready():
    helpers = _load()
    first = FakeCsonicHost("prime", "VrfARISTA01T2")
    second = FakeCsonicHost("prime", "VrfARISTA03T2")
    second.ready_vrfs = set()
    node = {
        "host": first,
        "csonic_t1_lag_peers": [
            {"host": first, "name": "ARISTA01T2"},
            {"host": second, "name": "ARISTA03T2"},
        ],
    }
    observed = []

    results = helpers["_run_csonic_t1_lag_gr_group"](
        node,
        lambda peer: observed.append(peer) or [{"failed": False}],
        start_bgpd=True,
    )

    assert first.start_count == 1
    assert observed == []
    assert results[-1]["failed"]
    assert "VrfARISTA03T2" in results[-1]["msg"]


def test_ceos_fixture_still_batches_all_vrfs_in_one_eos_config_call():
    helpers = _load(include_fixture=True)
    eos = FakeEosHost()
    primary = {
        "host": eos,
        "conf": {"bgp": {"asn": 64600}},
        "is_multi_vrf_peer": True,
        "multi_vrf_data": {
            "primary_host": "PRIMARY",
            "primary_host_asn": 64600,
            "vrf": "ARISTA01T2",
        },
    }
    second = {
        **primary,
        "multi_vrf_data": {
            **primary["multi_vrf_data"],
            "vrf": "ARISTA03T2",
        },
    }
    generator = helpers["setup_bgp_graceful_restart"](
        {"dut": FakeDut()}, "dut",
        {"PRIMARY": primary, "ARISTA03T2": second},
        T1_LAG,
    )

    next(generator)
    generator.close()

    assert len(eos.eos_configs) == 1
    config, kwargs = eos.eos_configs[0]
    assert "router bgp 64600" in config
    assert "vrf ARISTA01T2" in config
    assert "vrf ARISTA03T2" in config
    assert kwargs == {"module_ignore_errors": True}


@pytest.mark.parametrize(
    'host',
    [
        FakeSonicHost('sonic-neighbor'),
        FakeCsonicHost('ordinary-csonic'),
    ],
)
def test_sonic_and_ordinary_csonic_keep_legacy_fixture_commands(host):
    helpers = _load(include_fixture=True)
    generator = helpers['setup_bgp_graceful_restart'](
        {'dut': FakeDut()}, 'dut',
        {'NEIGHBOR': _peer(host, 'NEIGHBOR')},
        T1_LAG,
    )

    next(generator)
    generator.close()

    assert len(host.config_calls) == 3
    assert [call[0] for call in host.command_calls] == [
        "sudo vtysh -c 'clear bgp ipv4 *'",
        "sudo vtysh -c 'clear bgp ipv6 *'",
    ]
    assert host.start_count == 0


def test_t0_converged_csonic_fixture_retains_per_logical_peer_operations():
    helpers = _load(include_fixture=True)
    first = FakeCsonicHost("prime", "VrfARISTA01T0")
    second = FakeCsonicHost("prime", "VrfARISTA03T0")
    first.ready_vrfs.add("VrfARISTA01T0")
    second.ready_vrfs.add("VrfARISTA03T0")
    generator = helpers["setup_bgp_graceful_restart"](
        {"dut": FakeDut()}, "dut",
        {
            "ARISTA01T0": _peer(first, "ARISTA01T0"),
            "ARISTA03T0": _peer(second, "ARISTA03T0"),
        },
        T0,
    )

    next(generator)
    generator.close()

    assert len(first.config_calls) == 3
    assert len(second.config_calls) == 3
    assert len(first.command_calls) == 2
    assert len(second.command_calls) == 2
    assert first.start_count == second.start_count == 0
