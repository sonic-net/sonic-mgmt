"""Offline regressions for eBGP and Everflow fixture cleanup.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/fixtures/unit_test_ebgp_cleanup.py -v
"""

import ast
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from unittest.mock import Mock, call

import pytest


COMMON_DIR = Path(__file__).resolve().parents[2]
COMMON_FIXTURES = COMMON_DIR / "fixtures" / "duthost_utils.py"
EVERFLOW_UTILITIES = COMMON_DIR.parent / "everflow" / "everflow_test_utilities.py"
RUN_DIR = "/tmp/everflow"


def _load_functions(path, names, namespace):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == set(names)
    for function in functions:
        function.decorator_list = []
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)


def _mock_dut(hostname, v4_routes=100, v6_routes=200, directory_created=True):
    dut = Mock(hostname=hostname)
    dut.get_ip_route_summary.return_value = (
        {"ebgp": {"routes": v4_routes}},
        {"ebgp": {"routes": v6_routes}},
    )
    dut.shell.return_value = {"stdout": "12.5"}
    dut.file.return_value = {"changed": directory_created}
    return dut


class _DutHosts(list):
    def __getitem__(self, key):
        if isinstance(key, str):
            return next(dut for dut in self if dut.hostname == key)
        return super().__getitem__(key)

    @property
    def frontend_nodes(self):
        return list(self)


def _duts(created=(True, True, True)):
    return _DutHosts(
        _mock_dut("dut-{}".format(index), 100 * index, 200 * index, directory_created)
        for index, directory_created in enumerate(created, 1)
    )


def _fixture(namespace, fixture_name, duthosts, topo="t2", selected=None):
    selected = selected or duthosts[0].hostname
    if fixture_name == "shutdown_ebgp":
        return namespace[fixture_name](duthosts, selected)
    namespace["get_t2_duthost"].return_value = (duthosts[0], duthosts[-1])
    return namespace[fixture_name](duthosts, selected, {"topo": {"name": topo}}, None, "scenario")


def _restores(duthosts):
    return [
        call(dut, 100 * index, 200 * index)
        for index, dut in reversed(list(enumerate(duthosts, 1)))
    ]


@pytest.fixture
def cleanup_namespace():
    namespace = {
        "ExitStack": ExitStack,
        "partial": partial,
        "pytest": pytest,
        "logger": Mock(),
        "logging": Mock(),
        "wait_until": Mock(return_value=True),
        "check_ebgp_routes": Mock(),
        "check_orch_cpu_utilization": Mock(),
        "duthost_startup_ebgp": Mock(),
        "gen_setup_information": Mock(return_value={"topo": "t2"}),
        "get_t2_duthost": Mock(),
        "DUT_RUN_DIR": RUN_DIR,
    }
    _load_functions(COMMON_DIR / "helpers" / "assertions.py", ["pytest_assert"], namespace)
    namespace["pt_assert"] = namespace["pytest_assert"]
    _load_functions(COMMON_FIXTURES, [
        "duthost_shutdown_ebgp", "restore_ebgp_on_exit", "shutdown_ebgp",
    ], namespace)
    _load_functions(EVERFLOW_UTILITIES, ["_remove_run_dir_on_exit", "setup_info"], namespace)
    return namespace


@pytest.mark.parametrize("v4_routes,v6_routes,cpu_timeout", [
    (100, 200, 60),
    (0, 0, 60),
    (10000, 10000, 60),
    (10001, 200, 120),
    (100, 10001, 120),
])
def test_shutdown_success_preserves_baseline_and_readiness_gates(
        cleanup_namespace, v4_routes, v6_routes, cpu_timeout):
    """Keep the original route counts, thresholds, and successful shutdown behavior."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1", v4_routes, v6_routes)

    assert namespace["duthost_shutdown_ebgp"](dut) == (v4_routes, v6_routes)

    dut.command.assert_called_once_with("sudo config bgp shutdown all")
    assert namespace["wait_until"].call_args_list == [
        call(60, 2, 5, namespace["check_ebgp_routes"], 0, 0, dut),
        call(cpu_timeout, 2, 0, namespace["check_orch_cpu_utilization"], dut, 10),
    ]
    namespace["duthost_startup_ebgp"].assert_not_called()


def test_shutdown_route_snapshot_failure_does_not_mutate(cleanup_namespace):
    """Do not change peers or attempt restoration when the baseline cannot be read."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1")
    dut.get_ip_route_summary.side_effect = RuntimeError("snapshot failed")

    with pytest.raises(RuntimeError, match="snapshot failed"):
        namespace["duthost_shutdown_ebgp"](dut)

    dut.command.assert_not_called()
    namespace["duthost_startup_ebgp"].assert_not_called()


def test_shutdown_without_ebgp_baseline_keeps_zero_counts(cleanup_namespace):
    """Preserve the existing zero-route default when route summaries have no eBGP key."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1")
    dut.get_ip_route_summary.return_value = ({}, {})

    assert namespace["duthost_shutdown_ebgp"](dut) == (0, 0)
    namespace["duthost_startup_ebgp"].assert_not_called()


@pytest.mark.parametrize("gate,message", [
    ("routes", "eBGP routes are not 0"),
    ("cpu", "Orch CPU utilization"),
])
@pytest.mark.parametrize("restore_fails", [False, True])
def test_shutdown_gate_failure_restores_before_raising(cleanup_namespace, gate, message, restore_fails):
    """A failed readiness assertion restores the baseline and remains the primary error."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1")
    namespace["wait_until"].side_effect = [False] if gate == "routes" else [True, False]
    if restore_fails:
        namespace["duthost_startup_ebgp"].side_effect = RuntimeError("restore failed")

    with pytest.raises(pytest.fail.Exception, match=message):
        namespace["duthost_shutdown_ebgp"](dut)

    namespace["duthost_startup_ebgp"].assert_called_once_with(dut, 100, 200)
    assert namespace["logger"].exception.call_count == (2 if restore_fails else 1)


@pytest.mark.parametrize("stage", ["command", "wait", "diagnostic"])
@pytest.mark.parametrize("error_type", [RuntimeError, pytest.skip.Exception])
def test_shutdown_command_or_probe_error_preserves_original_exception(cleanup_namespace, stage, error_type):
    """Command, polling, and diagnostic exceptions also roll back without being replaced."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1")
    primary = error_type("setup failed")
    if stage == "command":
        dut.command.side_effect = primary
    elif stage == "wait":
        namespace["wait_until"].side_effect = primary
    else:
        dut.shell.side_effect = primary
    namespace["duthost_startup_ebgp"].side_effect = RuntimeError("restore failed")

    with pytest.raises(error_type) as caught:
        namespace["duthost_shutdown_ebgp"](dut)

    assert caught.value is primary
    namespace["duthost_startup_ebgp"].assert_called_once_with(dut, 100, 200)
    assert namespace["logger"].exception.call_count == 2


@pytest.mark.parametrize("error_type", [RuntimeError, pytest.fail.Exception])
def test_restore_exit_helper_propagates_cleanup_failures(cleanup_namespace, error_type):
    """A restoration failure must fail teardown when there is no earlier exception."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1")
    cleanup_error = error_type("restore failed")
    namespace["duthost_startup_ebgp"].side_effect = cleanup_error

    with pytest.raises(error_type) as caught:
        namespace["restore_ebgp_on_exit"](dut, 100, 200, None, None, None)

    assert caught.value is cleanup_error


@pytest.mark.parametrize("primary_type", [RuntimeError, pytest.fail.Exception, pytest.skip.Exception])
@pytest.mark.parametrize("cleanup_type", [RuntimeError, pytest.fail.Exception])
def test_restore_exit_helper_keeps_primary_failures(cleanup_namespace, primary_type, cleanup_type):
    """Log secondary restoration failures, including pytest outcomes, without suppressing the primary."""
    namespace = cleanup_namespace
    dut = _mock_dut("dut-1")
    primary = primary_type("setup failed")
    namespace["duthost_startup_ebgp"].side_effect = cleanup_type("restore failed")

    assert namespace["restore_ebgp_on_exit"](dut, 100, 200, primary_type, primary, None) is False
    namespace["logger"].exception.assert_called_once_with(
        "Failed to restore eBGP on %s while handling %s", "dut-1", primary_type.__name__)


def test_shared_fixture_normal_teardown_restores_in_lifo_order(cleanup_namespace):
    """Every successful shared-fixture shutdown has a matching reverse-order restoration."""
    namespace = cleanup_namespace
    duthosts = _duts()
    generator = _fixture(namespace, "shutdown_ebgp", duthosts)

    assert next(generator) is None
    namespace["duthost_startup_ebgp"].assert_not_called()
    with pytest.raises(StopIteration):
        next(generator)

    assert namespace["duthost_startup_ebgp"].call_args_list == _restores(duthosts)


@pytest.mark.parametrize("fixture_name", ["shutdown_ebgp", "setup_info"])
@pytest.mark.parametrize("restore_fails", [False, True])
def test_later_dut_failure_self_restores_and_unwinds_previous_duts(cleanup_namespace, fixture_name, restore_fails):
    """The failing DUT self-restores before earlier successful shutdowns are unwound."""
    namespace = cleanup_namespace
    duthosts = _duts()
    namespace["wait_until"].side_effect = [True, True, True, False]
    if restore_fails:
        namespace["duthost_startup_ebgp"].side_effect = [
            RuntimeError("failing DUT restore failed"),
            pytest.fail.Exception("earlier DUT restore failed"),
        ]
        if fixture_name == "setup_info":
            for dut in duthosts:
                dut.file.side_effect = [{"changed": True}, RuntimeError("directory removal failed")]
    generator = _fixture(namespace, fixture_name, duthosts)

    with pytest.raises(pytest.fail.Exception, match="Orch CPU utilization"):
        next(generator)

    assert namespace["duthost_startup_ebgp"].call_args_list == _restores(duthosts[:2])
    duthosts[2].command.assert_not_called()
    if fixture_name == "setup_info":
        for dut in duthosts:
            assert dut.file.call_args_list == [
                call(path=RUN_DIR, state="directory"), call(path=RUN_DIR, state="absent"),
            ]
        assert namespace["logging"].exception.call_count == (3 if restore_fails else 0)


@pytest.mark.parametrize("fixture_name", ["shutdown_ebgp", "setup_info"])
def test_teardown_attempts_every_restore_and_keeps_first_error(cleanup_namespace, fixture_name):
    """Failed restoration of one DUT does not block the rest or replace the first cleanup error."""
    namespace = cleanup_namespace
    duthosts = _duts()
    first_error = RuntimeError("dut-3 restore failed")
    namespace["duthost_startup_ebgp"].side_effect = [
        first_error, pytest.fail.Exception("dut-2 restore failed"), None,
    ]
    generator = _fixture(namespace, fixture_name, duthosts)
    next(generator)

    with pytest.raises(RuntimeError) as caught:
        next(generator)

    assert caught.value is first_error
    assert namespace["duthost_startup_ebgp"].call_args_list == _restores(duthosts)
    namespace["logger"].exception.assert_called_once()
    if fixture_name == "setup_info":
        for dut in duthosts:
            dut.file.assert_any_call(path=RUN_DIR, state="absent")


def test_everflow_normal_teardown_unwinds_all_resources_in_lifo_order(cleanup_namespace):
    """Restore every DUT before removing fixture-owned directories in reverse acquisition order."""
    namespace = cleanup_namespace
    duthosts = _duts()
    operations = Mock()
    operations.attach_mock(namespace["duthost_startup_ebgp"], "restore")
    for index, dut in enumerate(duthosts, 1):
        operations.attach_mock(dut.file, "dir{}".format(index))
    generator = _fixture(namespace, "setup_info", duthosts)

    assert next(generator) == {"topo": "t2"}
    with pytest.raises(StopIteration):
        next(generator)

    assert operations.mock_calls == [
        call.dir1(path=RUN_DIR, state="directory"),
        call.dir2(path=RUN_DIR, state="directory"),
        call.dir3(path=RUN_DIR, state="directory"),
        call.restore(duthosts[2], 300, 600),
        call.restore(duthosts[1], 200, 400),
        call.restore(duthosts[0], 100, 200),
        call.dir3(path=RUN_DIR, state="absent"),
        call.dir2(path=RUN_DIR, state="absent"),
        call.dir1(path=RUN_DIR, state="absent"),
    ]


@pytest.mark.parametrize("created", [(False, False, False), (False, True, False), (True, False, True)])
@pytest.mark.parametrize("setup_fails", [False, True])
def test_everflow_preserves_preexisting_run_directories(cleanup_namespace, created, setup_fails):
    """Never remove pre-existing directories on either normal teardown or failed setup."""
    namespace = cleanup_namespace
    duthosts = _duts(created)
    if setup_fails:
        namespace["duthost_shutdown_ebgp"] = Mock(side_effect=[
            (100, 200), (200, 400), pytest.skip.Exception("later setup skipped"),
        ])
    generator = _fixture(namespace, "setup_info", duthosts)

    if setup_fails:
        with pytest.raises(pytest.skip.Exception, match="later setup skipped"):
            next(generator)
    else:
        next(generator)
        with pytest.raises(StopIteration):
            next(generator)

    expected_restores = duthosts[:2] if setup_fails else duthosts
    assert namespace["duthost_startup_ebgp"].call_args_list == _restores(expected_restores)
    for dut, directory_created in zip(duthosts, created):
        expected = [call(path=RUN_DIR, state="directory")]
        if directory_created:
            expected.append(call(path=RUN_DIR, state="absent"))
        assert dut.file.call_args_list == expected


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_everflow_directory_creation_failure_unwinds_only_owned_resources(cleanup_namespace, cleanup_fails):
    """A failed later allocation removes earlier owned directories but never starts BGP setup."""
    namespace = cleanup_namespace
    duthosts = _duts()
    primary = RuntimeError("directory creation failed")
    duthosts[1].file.side_effect = primary
    if cleanup_fails:
        duthosts[0].file.side_effect = [
            {"changed": True}, pytest.fail.Exception("directory removal failed"),
        ]
    generator = _fixture(namespace, "setup_info", duthosts)

    with pytest.raises(RuntimeError) as caught:
        next(generator)

    assert caught.value is primary
    assert duthosts[0].file.call_args_list == [
        call(path=RUN_DIR, state="directory"), call(path=RUN_DIR, state="absent"),
    ]
    duthosts[1].file.assert_called_once_with(path=RUN_DIR, state="directory")
    duthosts[2].file.assert_not_called()
    for dut in duthosts:
        dut.command.assert_not_called()
    namespace["duthost_startup_ebgp"].assert_not_called()
    assert namespace["logging"].exception.call_count == (1 if cleanup_fails else 0)


def test_everflow_directory_cleanup_attempts_all_steps_and_keeps_first_error(cleanup_namespace):
    """Directory-only cleanup failures remain visible without blocking other removals."""
    namespace = cleanup_namespace
    duthosts = _duts()
    first_error = RuntimeError("dut-3 removal failed")
    duthosts[2].file.side_effect = [{"changed": True}, first_error]
    duthosts[1].file.side_effect = [{"changed": True}, pytest.fail.Exception("dut-2 removal failed")]
    generator = _fixture(namespace, "setup_info", duthosts)
    next(generator)

    with pytest.raises(RuntimeError) as caught:
        next(generator)

    assert caught.value is first_error
    assert namespace["duthost_startup_ebgp"].call_args_list == _restores(duthosts)
    for dut in duthosts:
        dut.file.assert_any_call(path=RUN_DIR, state="absent")
    namespace["logging"].exception.assert_called_once()


def test_everflow_bgp_cleanup_error_wins_over_directory_cleanup_errors(cleanup_namespace):
    """Directory failures cannot replace an earlier BGP restoration error."""
    namespace = cleanup_namespace
    duthosts = _duts()
    primary = RuntimeError("BGP restore failed")
    namespace["duthost_startup_ebgp"].side_effect = [primary, None, None]
    for dut in duthosts:
        dut.file.side_effect = [{"changed": True}, RuntimeError("directory removal failed")]
    generator = _fixture(namespace, "setup_info", duthosts)
    next(generator)

    with pytest.raises(RuntimeError) as caught:
        next(generator)

    assert caught.value is primary
    assert namespace["duthost_startup_ebgp"].call_args_list == _restores(duthosts)
    assert namespace["logging"].exception.call_count == 3


@pytest.mark.parametrize("error_type", [RuntimeError, pytest.skip.Exception])
def test_everflow_information_failure_leaves_resources_untouched(cleanup_namespace, error_type):
    """An unsupported or failed information-gathering step acquires no resources."""
    namespace = cleanup_namespace
    duthosts = _duts()
    primary = error_type("no setup information")
    namespace["gen_setup_information"].side_effect = primary
    generator = _fixture(namespace, "setup_info", duthosts)

    with pytest.raises(error_type) as caught:
        next(generator)

    assert caught.value is primary
    for dut in duthosts:
        dut.file.assert_not_called()
        dut.command.assert_not_called()
    namespace["duthost_startup_ebgp"].assert_not_called()


@pytest.mark.parametrize("topo,count", [
    ("t0", 3), ("t1", 3), ("m0", 3), ("mx", 3), ("lt2", 1), ("ft2", 1), ("t2", 3),
])
def test_everflow_preserves_topology_selection(cleanup_namespace, topo, count):
    """Keep selected-DUT setup outside T2 and whole-frontend setup for a T2 chassis."""
    namespace = cleanup_namespace
    duthosts = _duts((True,) * count)
    selected = duthosts[-1]
    generator = _fixture(namespace, "setup_info", duthosts, topo, selected.hostname)
    next(generator)
    with pytest.raises(StopIteration):
        next(generator)

    targets = duthosts if topo == "t2" else [selected]
    assert namespace["duthost_startup_ebgp"].call_args_list == [
        call(dut, *[summary["ebgp"]["routes"] for summary in dut.get_ip_route_summary.return_value])
        for dut in reversed(targets)
    ]
    for dut in duthosts:
        if dut in targets:
            assert dut.file.call_args_list == [
                call(path=RUN_DIR, state="directory"), call(path=RUN_DIR, state="absent"),
            ]
            dut.command.assert_called_once_with("sudo config bgp shutdown all")
        else:
            dut.file.assert_not_called()
            dut.command.assert_not_called()
