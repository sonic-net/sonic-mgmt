"""Exercise actual route-stress ASTs without hardware fixtures or Git history."""

import ast
import copy
import json
import logging
import sys
import traceback
from collections import UserDict, UserString, deque
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = ROOT / "tests" / "stress" / "test_stress_routes.py"
FUNCTIONS = (
    "get_route_state", "wait_for_route_convergence", "change_routes_and_wait",
    "withdraw_and_restore_routes", "announce_withdraw_routes",
    "test_announce_withdraw_route", "check_memory_usage_is_expected",
)
CONSTANTS = ("ALLOW_ROUTES_CHANGE_NUMS", "CRM_POLLING_INTERVAL", "MAX_WAIT_TIME", "LOOP_TIMES_LEVEL_MAP")


def load_functions(path, names, namespace):
    """Compile actual functions, stripping fixture decorators but not function bodies."""
    nodes = []
    found = set()
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            node.decorator_list = []
            nodes.append(node)
            found.add(node.name)
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in CONSTANTS for target in node.targets
        ):
            nodes.append(node)
    assert found == set(names), "Missing actual functions: {}".format(set(names) - found)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def assertion(condition, message=""):
    """Match pytest_assert without importing integration-test dependencies."""
    if not condition:
        pytest.fail(message)


def state(bgp, crm, peers=None, queues=None, ready=True, peer_names=None):
    """Construct the genuine route-state shape using synthetic peer identities."""
    peers = ({"v4": bgp[0]}, {"v6": bgp[1]}) if peers is None else peers
    return {
        "bgp": tuple(bgp), "crm": tuple(crm), "peers": peers,
        "peer_names": tuple({address: "vm" for address in family} for family in peers)
        if peer_names is None else peer_names,
        "queues": {"inq": (0, 0), "outq": (0, 0)} if queues is None else queues,
        "ready": ready,
    }


class AnsibleText(str):
    """Model unsafe/tagged text without importing Ansible."""


def wrapped(value):
    """Model nested Ansible module-result Mapping wrappers and text subclasses."""
    if isinstance(value, dict):
        return UserDict({key: wrapped(item) for key, item in value.items()})
    if isinstance(value, str):
        return AnsibleText(value)
    if isinstance(value, list):
        return [wrapped(item) for item in value]
    if isinstance(value, tuple):
        return tuple(wrapped(item) for item in value)
    return value


class DutHosts(dict):
    """Provide the selected host and frontend-node interface used by the real body."""

    def __init__(self, dut):
        super().__init__({dut.hostname: dut})

    @property
    def frontend_nodes(self):
        """Derive frontend nodes from the mapping so dictionary equality remains complete."""
        return list(self.values())


def test_duthosts_frontend_nodes_track_mapping_values():
    """The test helper exposes every mapped frontend DUT without hidden equality state."""
    first = Mock(hostname="dut-1")
    second = Mock(hostname="dut-2")
    duthosts = DutHosts(first)
    duthosts[second.hostname] = second

    assert duthosts.frontend_nodes == [first, second]


class Runtime:
    """Run production functions and the actual shared poller on a virtual clock."""

    def __init__(self, initial, frames=None, transitions=None, asic_type="physical", namespace="asic0"):
        self.initial = copy.deepcopy(initial)
        self.frames = frames
        self.transitions = list(transitions or [])
        self.active = None
        self.action_started = 0
        self.action = None
        self.elapsed = 0
        self.events = []
        self.polls = []
        self.logger = Mock()
        self.shell_override = None
        self.summary_override = None
        self.resources_override = None
        self.use_wrappers = False
        self.namespace = namespace
        self.memory_samples = [{"bgpd": 0, "zebra": 0}, {"bgpd": 0, "zebra": 0}]
        self.memory_calls = []
        self.receipt = {
            "changed": True, "topo_routes": {
                "vm": {"ipv4": [("192.0.2.0/24", "192.0.2.1", "")],
                       "ipv6": [("2001:db8::/64", "2001:db8::1", "")]},
            },
        }
        self.dut = SimpleNamespace(
            hostname="dut", facts={"asic_type": asic_type, "hwsku": "offline"},
            os_version="202605", sonic_release="202605", loganalyzer=False,
            shell=self.shell, get_crm_resources=self.resources,
            get_vtysh_cmd_for_namespace=self.vtysh,
            asic_instance=lambda index: SimpleNamespace(namespace=namespace),
        )
        self.localhost = SimpleNamespace(announce_routes=self.submit)
        base = {
            "json": json, "logging": logging, "logger": self.logger,
            "sys": sys, "traceback": traceback, "deque": deque, "Mapping": Mapping,
            "pytest": pytest, "pytest_assert": assertion,
            "time": SimpleNamespace(time=lambda: self.elapsed, sleep=self.sleep),
        }
        poller = load_functions(ROOT / "tests" / "common" / "utilities.py", ("wait_until",), dict(base))
        self.repository_wait_until = poller["wait_until"]
        base.update(
            wait_until=self.wait_until, get_crm_resource_status=self.crm,
            sleep_to_wait=self.sleep, get_frr_daemon_memory_usage=self.memory,
        )
        load_functions(ROOT / "tests" / "stress" / "utils.py", (), base)
        self.functions = load_functions(PRODUCTION, FUNCTIONS, base)

    def current(self):
        if self.frames is not None:
            return copy.deepcopy(self.frames[min(int(self.elapsed), len(self.frames) - 1)])
        if self.active is not None:
            for delay, sample in reversed(self.active):
                if self.elapsed - self.action_started >= delay:
                    return copy.deepcopy(sample)
        return copy.deepcopy(self.initial)

    def vtysh(self, command, namespace):
        self.events.append(("namespace", namespace))
        return command

    def shell(self, command):
        if self.shell_override is not None:
            return self.shell_override(self.elapsed)
        sample = self.current()
        summary = self.summary_override
        if callable(summary):
            summary = summary(self.elapsed)
        if summary is None:
            summary = {
                family: {"peers": {
                    address: {
                        "pfxRcd": count, "state": "Established" if sample["ready"] else "Active",
                        "desc": sample["peer_names"][index].get(address),
                        **{queue: sample["queues"][queue][index] for queue in ("inq", "outq")},
                    }
                    for address, count in sample["peers"][index].items()
                }}
                for index, family in enumerate(("ipv4Unicast", "ipv6Unicast"))
            }
        result = {"stdout": json.dumps(summary), "rc": 0, "failed": False}
        return wrapped(result) if self.use_wrappers else result

    def resources(self, namespace):
        self.events.append(("crm_namespace", namespace))
        if self.resources_override is not None:
            return self.resources_override(self.elapsed)
        counts = self.current()["crm"]
        result = {"main_resources": {
            "ipv4_route": {"used": counts[0]}, "ipv6_route": {"used": counts[1]},
        }}
        return wrapped(result) if self.use_wrappers else result

    def crm(self, dut, family, counter, namespace):
        return self.resources(namespace)["main_resources"][family][counter]

    def submit(self, **kwargs):
        previous = self.current()
        self.action = kwargs["action"]
        self.events.append(("action", self.elapsed, self.action))
        self.initial = previous
        self.action_started = self.elapsed
        if self.transitions:
            action, self.active = self.transitions.pop(0)
            assert self.action == action
        receipt = self.receipt(self.action) if callable(self.receipt) else self.receipt
        if isinstance(receipt, BaseException):
            raise receipt
        return wrapped(receipt) if self.use_wrappers else copy.deepcopy(receipt)

    def sleep(self, seconds):
        self.events.append(("sleep", self.elapsed, seconds))
        self.elapsed += seconds

    def wait_until(self, timeout, interval, delay, predicate, *args, **kwargs):
        self.polls.append((timeout, interval, delay))
        return self.repository_wait_until(timeout, interval, delay, predicate, *args, **kwargs)

    def memory(self, dut, daemons, namespace):
        self.memory_calls.append((tuple(daemons), namespace))
        return self.memory_samples[min(len(self.memory_calls) - 1, len(self.memory_samples) - 1)]

    def converge(self, before, action="announce", families=(True, True), expected=None):
        return self.functions["wait_for_route_convergence"](
            self.dut, self.namespace, action, before, families, expected,
        )

    def change(self, before, action="announce", expected=None):
        return self.functions["change_routes_and_wait"](
            self.dut, self.namespace, self.localhost, "offline", "t1", action, before, expected,
        )

    def fixture(self):
        return self.functions["withdraw_and_restore_routes"](
            DutHosts(self.dut), self.localhost, {"ptf_ip": "offline", "topo": {"name": "t1"}},
            self.dut.hostname, 0, None, None,
        )

    def body(self, baselines, level=None, loganalyzer=None):
        return self.functions["test_announce_withdraw_route"](
            DutHosts(self.dut), self.localhost, {"ptf_ip": "offline", "topo": {"name": "t1"}},
            level, baselines, loganalyzer or {}, self.dut.hostname, 0, None,
        )


def expect_timeout(runtime, before, **kwargs):
    with pytest.raises(pytest.fail.Exception, match="Routes failed to converge.*220") as caught:
        runtime.converge(before, **kwargs)
    for token in ("namespace=", "before=", "families=", "expected=", "samples="):
        assert token in str(caught.value)
    assert runtime.polls[-1] == (220, 1, 1)
    assert runtime.elapsed == 221


@pytest.mark.parametrize("namespace", [None, "asic3"])
@pytest.mark.parametrize("use_wrappers", [False, True])
def test_actual_state_reader_accepts_mapping_text_and_scopes_namespace(namespace, use_wrappers):
    """Actual source accepts nested module-result wrappers without changing ASIC scope."""
    initial = state((50, 60), (80, 90))
    runtime = Runtime(initial, namespace=namespace)
    runtime.use_wrappers = use_wrappers
    assert runtime.functions["get_route_state"](runtime.dut, namespace) == initial
    assert ("namespace", namespace) in runtime.events
    assert ("crm_namespace", namespace) in runtime.events


@pytest.mark.parametrize("payload", [
    None, [], {}, {"failed": True, "stdout": "{}"}, {"stdout": b"{}"},
    {"stdout": UserString("{}")}, {"stdout": None}, {"stdout": "{"},
    {"stdout": "null"}, {"stdout": "[]"},
])
def test_invalid_shell_results_and_json_fail_explicitly(payload):
    """Missing/non-text/failed shell results and malformed JSON are not coerced into success."""
    runtime = Runtime(state((0, 0), (10, 20)))
    runtime.shell_override = lambda elapsed: wrapped(payload)
    with pytest.raises(pytest.fail.Exception, match="Invalid BGP"):
        runtime.functions["get_route_state"](runtime.dut, "asic0")


@pytest.mark.parametrize("payload", [
    None, {}, {"main_resources": None}, {"main_resources": {}},
    {"main_resources": {"ipv4_route": {"used": 1}, "ipv6_route": {}}},
    *[{"main_resources": {"ipv4_route": {"used": value}, "ipv6_route": {"used": 20}}}
      for value in (True, -1, "10", 1.5)],
])
def test_invalid_nested_crm_and_numeric_counters_fail_explicitly(payload):
    """Mapping compatibility preserves required fields and strict nonnegative integer counters."""
    runtime = Runtime(state((0, 0), (10, 20)))
    runtime.resources_override = lambda elapsed: wrapped(payload)
    with pytest.raises(pytest.fail.Exception, match="Invalid route CRM"):
        runtime.functions["get_route_state"](runtime.dut, "asic0")


@pytest.mark.parametrize("field,value", [
    ("pfxRcd", True), ("pfxRcd", -1), ("inq", "0"), ("outq", None), ("state", None),
])
def test_invalid_bgp_peer_data_cannot_look_like_empty_queues(field, value):
    """Malformed peer state, queue or prefix fields remain errors."""
    runtime = Runtime(state((0, 0), (10, 20)))
    record = {"pfxRcd": 0, "inq": 0, "outq": 0, "state": "Established", field: value}
    runtime.summary_override = {"ipv4Unicast": {"peers": {"v4": record}}}
    with pytest.raises(pytest.fail.Exception, match="Invalid BGP peer"):
        runtime.functions["get_route_state"](runtime.dut, "asic0")


def test_independent_family_bgp_and_crm_delays_require_two_eligible_samples():
    """Neither one family nor BGP alone permits an overlapping route action."""
    before = state((0, 0), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(before, frames=[
        before, state((50, 0), (10, 20)), state((50, 0), (80, 20)),
        state((50, 60), (80, 20)), target, target,
    ])
    assert runtime.converge(before, expected=target) == target
    assert runtime.elapsed == 5


@pytest.mark.parametrize("sample", [
    state((10, 20), (30, 40)), state((50, 60), (30, 40)),
    state((10, 20), (80, 90)), state((5, 10), (20, 30)),
])
def test_stale_partial_and_wrong_direction_progress_time_out(sample):
    """Stable pre-submission, one-counter and wrong-direction observations cannot converge."""
    before = state((10, 20), (30, 40))
    expect_timeout(Runtime(sample), before)


@pytest.mark.parametrize("queue", ["inq", "outq"])
@pytest.mark.parametrize("family", [0, 1])
@pytest.mark.parametrize("action", ["announce", "withdraw"])
def test_both_family_input_and_output_queues_gate_both_actions(queue, family, action):
    """All four selected-ASIC queues gate announcements and withdrawals."""
    before = state((0, 0), (10, 20)) if action == "announce" else state((100, 100), (200, 200))
    counts = [0, 0]
    counts[family] = 1
    queues = {"inq": (0, 0), "outq": (0, 0), queue: tuple(counts)}
    target = state((50, 60), (80, 90))
    sample = state(target["bgp"], target["crm"], queues=queues)
    expect_timeout(Runtime(sample), before, action=action, expected=target)


@pytest.mark.parametrize("ineligible", [
    state((50, 60), (80, 90), ready=False),
    state((50, 60), (80, 90), queues={"inq": (0, 1), "outq": (0, 0)}),
])
def test_down_peer_or_reopened_queue_breaks_consecutive_sampling(ineligible):
    """Eligibility, not merely adjacent equal totals, controls consecutive stability."""
    before = state((0, 0), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(before, frames=[before, target, ineligible, target, target])
    assert runtime.converge(before, expected=target) == target
    assert runtime.elapsed == 4


@pytest.mark.parametrize("failure", ["transport", "invalid_json", "invalid_crm"])
def test_shared_poller_exception_policy_cannot_accept_failed_observations(failure):
    """Existing pollers may retry invalid data or fail immediately, but cannot bridge a bad sample."""
    before = state((0, 0), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(target)
    shell, resources = runtime.shell, runtime.resources

    def observe(elapsed):
        if elapsed == 2:
            if failure == "transport":
                raise RuntimeError("synthetic transport error")
            return {"stdout": "{"}
        return shell("vtysh")

    if failure == "invalid_crm":
        runtime.dut.get_crm_resources = lambda namespace: {} if runtime.elapsed == 2 else resources(namespace)
    else:
        runtime.dut.shell = lambda command: observe(runtime.elapsed)
    try:
        result = runtime.converge(before, expected=target)
    except pytest.fail.Exception as error:
        assert failure != "transport" and runtime.elapsed == 2
        assert "Invalid BGP JSON" in str(error) or "Invalid route CRM" in str(error)
    else:
        assert result == target and runtime.elapsed == 4
        assert "Exception caught while checking" in runtime.logger.error.call_args.args[0]


def test_known_targets_wait_through_a_stable_partial_plateau():
    """Directional progress does not waive fixture-owned announced targets."""
    before = state((0, 0), (10, 20))
    partial = state((25, 30), (40, 50))
    target = state((50, 60), (80, 90))
    expect_timeout(Runtime(partial), before, expected=target)
    runtime = Runtime(before, frames=[before, partial, partial, partial, target, target])
    assert runtime.converge(before, expected=target) == target
    assert runtime.elapsed == 5


def test_peer_identity_and_per_peer_targets_cannot_be_replaced_by_aggregate_totals():
    """Redistributed prefixes and replaced peer identities cannot satisfy known targets."""
    before = state((0, 0), (10, 20), peers=({"a": 0, "b": 0}, {"v6": 0}))
    target = state((50, 60), (80, 90), peers=({"a": 20, "b": 30}, {"v6": 60}))
    redistributed = state((50, 60), (80, 90), peers=({"a": 30, "b": 20}, {"v6": 60}))
    expect_timeout(Runtime(redistributed), before, expected=target)
    replaced = state((50, 60), (80, 90), peers=({"a": 20, "other": 30}, {"v6": 60}))
    expect_timeout(Runtime(replaced), before, expected=target)


@pytest.mark.parametrize("drift,accepted", [(4, True), (5, False)])
def test_known_crm_target_retains_strict_tolerance(drift, accepted):
    """Known CRM counters permit drift four but never drift five."""
    before = state((0, 0), (10, 20))
    target = state((50, 60), (80, 90))
    sample = state((50, 60), (80 + drift, 90))
    runtime = Runtime(sample)
    if accepted:
        assert runtime.converge(before, expected=target) == sample
    else:
        expect_timeout(runtime, before, expected=target)


def test_explicitly_unchanged_known_target_is_a_noop_not_a_progress_timeout():
    """An already known target is valid only when both peer counts and CRM stay unchanged."""
    before = state((50, 60), (80, 90))
    runtime = Runtime(before)
    assert runtime.converge(before, action="withdraw", expected=before) == before
    assert runtime.elapsed == 2


@pytest.mark.parametrize("empty", [True, False])
def test_changed_receipt_never_proves_route_progress(empty):
    """Empty receipts require unchanged state, while nonempty receipts require real progress."""
    before = state((0, 0), (10, 20))
    runtime = Runtime(before)
    if empty:
        runtime.receipt = {"changed": True, "topo_routes": UserDict()}
        assert runtime.change(before) == before
    else:
        with pytest.raises(pytest.fail.Exception, match="Routes failed to converge"):
            runtime.change(before)


def test_empty_receipt_rejects_unrelated_bgp_change():
    """No-op receipts do not excuse unexpected peer-count changes."""
    before = state((0, 0), (10, 20))
    runtime = Runtime(state((50, 60), (80, 90)))
    runtime.receipt = {"changed": True, "topo_routes": {}}
    with pytest.raises(pytest.fail.Exception, match="Routes failed to converge"):
        runtime.change(before)


def test_receipts_are_scoped_to_selected_asic_peer_names():
    """Routes submitted to other VMs do not impose a locally absent family change."""
    before = state((0, 2), (10, 30))
    target = state((50, 2), (80, 30))
    runtime = Runtime(target)
    routes = runtime.receipt["topo_routes"]["vm"]
    runtime.receipt["topo_routes"] = {
        "vm": {"ipv4": routes["ipv4"], "ipv6": []},
        "other_vm": {"ipv6": routes["ipv6"]},
    }
    assert runtime.change(before) == target


def test_unmapped_peer_names_warn_and_do_not_waive_progress():
    """Older summaries use conservative topology-wide progress rather than silent no-ops."""
    before = state((0, 0), (10, 20), peer_names=({"v4": None}, {"v6": None}))
    runtime = Runtime(before)
    with pytest.raises(pytest.fail.Exception, match="Routes failed to converge"):
        runtime.change(before)
    assert "Cannot scope" in runtime.logger.warning.call_args.args[0]


def test_unconfigured_family_is_a_namespace_local_noop():
    """An absent BGP family can coexist with real progress in the configured family."""
    before = state((0, 0), (10, 20), peers=({}, {"v6": 0}))
    target = state((0, 60), (10, 90), peers=({}, {"v6": 60}))
    runtime = Runtime(target)
    assert runtime.change(before) == target
    runtime.summary_override = {"ipv6Unicast": {"peers": {
        "v6": {"pfxRcd": 60, "inq": 0, "outq": 0, "state": "Established", "desc": "vm"},
    }}}
    assert runtime.functions["get_route_state"](runtime.dut, "asic0") == target


def test_vs_still_checks_bgp_without_physical_crm_progress_or_stability():
    """VS preserves peer/queue/target checks while excluding unsupported CRM behavior."""
    before = state((0, 0), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(target, asic_type="vs", frames=[
        before, state((50, 60), (10, 20)), state((50, 60), (100, 200)),
    ])
    assert runtime.converge(before, expected=target)["bgp"] == target["bgp"]
    assert runtime.elapsed == 2


@pytest.mark.parametrize("receipt", [
    None, {}, {"failed": True, "topo_routes": {}}, {"topo_routes": None},
    {"topo_routes": {"vm": []}}, {"topo_routes": {"vm": {"ipv4": "not routes"}}},
    {"topo_routes": {"vm": {"ipv4": [("192.0.2.0/24",)]}}},
])
def test_invalid_receipts_fail_before_polling(receipt):
    """Mapping support never admits failed, missing or malformed topology route receipts."""
    runtime = Runtime(state((0, 0), (10, 20)))
    runtime.receipt = receipt
    with pytest.raises(pytest.fail.Exception, match="Route action"):
        runtime.change(runtime.initial)
    assert not runtime.polls


@pytest.mark.parametrize("level", [None, "debug", "basic", "confident", "thorough", "diagnose"])
def test_actual_stress_body_preserves_completeness_counts_and_final_settle(level):
    """Execute the actual test body for every completeness level without wall-clock sleeps."""
    before = state((1, 1), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(before)
    loops = runtime.functions["LOOP_TIMES_LEVEL_MAP"]["debug" if level is None else level]
    runtime.transitions = [
        transition for _ in range(loops)
        for transition in (("announce", [(1, target)]), ("withdraw", [(1, before)]))
    ]
    baselines = {"withdrawn": before, "announced": target}
    saved = copy.deepcopy(baselines)
    runtime.body(baselines, level)
    assert [event[2] for event in runtime.events if event[0] == "action"] == ["announce", "withdraw"] * loops
    assert runtime.transitions == [] and baselines == saved
    assert runtime.memory_calls == [(("bgpd", "zebra"), "asic0")] * 2
    assert ("sleep", loops * 6, 120) in runtime.events


@pytest.mark.parametrize("family", [0, 1])
@pytest.mark.parametrize("drift", [4, 5])
def test_actual_final_crm_assertion_retains_strict_less_than_five(family, drift):
    """The real final assertion rejects drift five after the existing 120-second settle."""
    before = state((1, 1), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(before, transitions=[("announce", [(1, target)]), ("withdraw", [(1, before)])])

    def resources(elapsed):
        counts = list(runtime.current()["crm"])
        if elapsed >= 126:
            counts[family] += drift
        return {"main_resources": {"ipv4_route": {"used": counts[0]}, "ipv6_route": {"used": counts[1]}}}

    runtime.resources_override = resources
    if drift == 4:
        runtime.body({"withdrawn": before, "announced": target})
    else:
        with pytest.raises(pytest.fail.Exception, match="route used before=.*after="):
            runtime.body({"withdrawn": before, "announced": target})


@pytest.mark.parametrize("daemon,limit", [("bgpd", 100), ("zebra", 200)])
@pytest.mark.parametrize("at_limit", [False, True])
def test_actual_memory_assertions_are_not_bypassed(daemon, limit, at_limit):
    """The real memory check accepts below-limit growth and rejects the strict boundary."""
    before = state((1, 1), (10, 20))
    target = state((50, 60), (80, 90))
    runtime = Runtime(before, transitions=[("announce", [(1, target)]), ("withdraw", [(1, before)])])
    runtime.memory_samples[1][daemon] = limit if at_limit else limit - 1
    if at_limit:
        with pytest.raises(pytest.fail.Exception, match="increase memory"):
            runtime.body({"withdrawn": before, "announced": target})
    else:
        runtime.body({"withdrawn": before, "announced": target})


def test_mapping_wrappers_complete_fixture_body_and_restoration():
    """Real fixture, body and teardown retain immutable targets through Mapping/text adapters."""
    announced = state((50, 60), (80, 90))
    withdrawn = state((1, 1), (10, 20))
    runtime = Runtime(announced, transitions=[
        ("withdraw", [(3, withdrawn)]), ("announce", [(3, announced)]),
        ("withdraw", [(3, withdrawn)]), ("announce", [(3, announced)]),
    ])
    runtime.use_wrappers = True
    generator = runtime.fixture()
    baselines = next(generator)
    saved = copy.deepcopy(baselines)
    runtime.body(baselines)
    assert baselines == saved and baselines["withdrawn"] == withdrawn
    with pytest.raises(StopIteration):
        next(generator)
    assert runtime.current() == announced
    assert [event[2] for event in runtime.events if event[0] == "action"] == [
        "withdraw", "announce", "withdraw", "announce",
    ]


@pytest.mark.parametrize("failure", ["timeout", "submission", "receipt"])
def test_setup_failures_still_restore_routes(failure):
    """Initial withdrawal timeout, partial submission and malformed receipt all restore."""
    announced = state((50, 60), (80, 90))
    runtime = Runtime(announced)
    if failure != "timeout":
        runtime.receipt = lambda action: (
            RuntimeError("partial submission") if failure == "submission" else {"topo_routes": None}
        ) if action == "withdraw" else {"topo_routes": {"vm": {"ipv4": [], "ipv6": []}}}
    exception = RuntimeError if failure == "submission" else pytest.fail.Exception
    with pytest.raises(exception):
        next(runtime.fixture())
    assert [event[2] for event in runtime.events if event[0] == "action"] == ["withdraw", "announce"]
    assert runtime.current() == announced


@pytest.mark.parametrize("phase", ["setup", "body"])
def test_primary_failure_is_preserved_with_restore_failure_chained(phase):
    """Cleanup failure is visible without replacing the original setup/body error."""
    announced = state((50, 60), (80, 90))
    withdrawn = state((1, 1), (10, 20))
    primary, cleanup = RuntimeError("primary failure"), RuntimeError("restore failure")
    runtime = Runtime(announced, transitions=[("withdraw", [(1, withdrawn)])])
    normal = runtime.receipt
    runtime.receipt = lambda action: (
        primary if phase == "setup" else normal
    ) if action == "withdraw" else cleanup
    generator = runtime.fixture()
    with pytest.raises(RuntimeError, match="primary failure") as caught:
        if phase == "setup":
            next(generator)
        else:
            next(generator)
            generator.throw(primary)
    assert caught.value is primary and caught.value.__cause__ is cleanup
    assert [event[2] for event in runtime.events if event[0] == "action"] == ["withdraw", "announce"]


def test_restore_submission_does_not_require_another_pre_cleanup_dut_read():
    """A failed observation cannot prevent submission of the final route announcement."""
    announced = state((50, 60), (80, 90))
    withdrawn = state((1, 1), (10, 20))
    runtime = Runtime(announced, transitions=[("withdraw", [(1, withdrawn)]), ("announce", [(1, announced)])])
    generator = runtime.fixture()
    next(generator)
    shell = runtime.dut.shell

    def read_after_submission(command):
        assert runtime.action == "announce", "Attempted a DUT read before restoration submission"
        return shell(command)

    runtime.dut.shell = read_after_submission
    generator.close()
    assert runtime.current() == announced


def test_unknown_announced_family_requires_real_restore_progress():
    """An initially empty configured family does not invent a zero announced target."""
    empty = state((0, 0), (10, 20))
    announced = state((50, 60), (80, 90))
    runtime = Runtime(empty, transitions=[("withdraw", [(1, empty)]), ("announce", [(1, announced)])])
    generator = runtime.fixture()
    baselines = next(generator)
    assert baselines["announced"]["bgp"] == (None, None)
    generator.close()
    assert runtime.current() == announced


def test_cycle_cannot_rebase_a_contaminated_withdrawn_baseline():
    """A changed baseline fails before the next announcement rather than hiding CRM leakage."""
    withdrawn = state((1, 1), (10, 20))
    runtime = Runtime(state((1, 1), (15, 20)))
    with pytest.raises(pytest.fail.Exception, match="Routes failed to converge"):
        runtime.functions["announce_withdraw_routes"](
            runtime.dut, "asic0", runtime.localhost, "offline", "t1",
            {"withdrawn": withdrawn, "announced": state((50, 60), (80, 90))},
        )
    assert not [event for event in runtime.events if event[0] == "action"]


def test_fixture_dependencies_and_topology_marker_shape():
    """Preserve cleanup dependencies and common coverage with optional paired UMA/LMA markers."""
    tree = ast.parse(PRODUCTION.read_text(encoding="utf-8"))
    fixture = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == "withdraw_and_restore_routes")
    assert ast.literal_eval(fixture.decorator_list[0].keywords[0].value) == "module"
    arguments = {argument.arg for argument in fixture.args.args}
    assert {
        "enum_rand_one_per_hwsku_frontend_hostname", "enum_rand_one_frontend_asic_index",
        "cleanup_neighbors_dualtor", "set_polling_interval",
    } <= arguments
    markers = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets))
    topologies = [ast.literal_eval(argument) for argument in markers.elts[0].args]
    assert [topology for topology in topologies if topology not in ("uma", "lma")] == [
        "t0", "t1", "m0", "mx", "m1", "t2", "lrh", "urh", "lt2", "ft2",
    ]
    assert ("uma" in topologies) == ("lma" in topologies)
