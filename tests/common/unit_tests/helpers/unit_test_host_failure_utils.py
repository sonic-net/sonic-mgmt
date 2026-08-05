import importlib.util
from types import SimpleNamespace
from unittest.mock import MagicMock
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2] /
    "helpers/host_failure_utils.py"
)
SPEC = importlib.util.spec_from_file_location(
    "unit_target_host_failure_utils", MODULE_PATH)
HOST_FAILURE_UTILS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST_FAILURE_UTILS)
HOST_FAILURE_UTILS.logger = MagicMock()

DUTHOSTS_FIXTURE_FAILED_CACHE_KEY = (
    HOST_FAILURE_UTILS.DUTHOSTS_FIXTURE_FAILED_CACHE_KEY
)
TESTBED_UNREACHABLE_STOP_REASON = (
    HOST_FAILURE_UTILS.TESTBED_UNREACHABLE_STOP_REASON
)
is_testbed_unreachable_exception = (
    HOST_FAILURE_UTILS.is_testbed_unreachable_exception
)
stop_on_testbed_unreachable = (
    HOST_FAILURE_UTILS.stop_on_testbed_unreachable
)


class FakeConnectionFailure(Exception):
    def __init__(self, message, dark=None):
        super().__init__(message)
        self.dark = dark


class FakeCoreConnectionFailure(Exception):
    pass


def _make_node(cache_value=None, shouldstop=False):
    cache = MagicMock()
    cache.get.return_value = cache_value
    config = SimpleNamespace(cache=cache)
    session = SimpleNamespace(shouldstop=shouldstop)
    return SimpleNamespace(
        config=config,
        session=session,
        name="test_example",
    )


def _make_call(exc=None, when="setup"):
    excinfo = None if exc is None else SimpleNamespace(value=exc)
    return SimpleNamespace(excinfo=excinfo, when=when)


def test_detects_ansible_connection_failure_type():
    exc = FakeConnectionFailure("authentication detail")

    assert is_testbed_unreachable_exception(
        exc, FakeConnectionFailure)


def test_detects_connection_failure_type_tuple():
    exc = FakeCoreConnectionFailure("connection detail")

    assert is_testbed_unreachable_exception(
        exc, (FakeConnectionFailure, FakeCoreConnectionFailure))


def test_detects_wrapped_host_unreachable():
    exc = RuntimeError(
        "Thread worker aborted: Host unreachable in the inventory")

    assert is_testbed_unreachable_exception(exc)


def test_detects_connection_failure_in_exception_cause():
    inner = FakeConnectionFailure(
        "connection detail", dark={"dut-1": {}})
    outer = RuntimeError()
    outer.__cause__ = inner

    assert is_testbed_unreachable_exception(
        outer, FakeConnectionFailure)


def test_detects_connection_failure_in_exception_group():
    group = ExceptionGroup(
        "parallel fixture failed",
        [FakeCoreConnectionFailure("connection detail")],
    )

    assert is_testbed_unreachable_exception(
        group, FakeCoreConnectionFailure)


def test_detects_dut_not_start_connectivity_failure():
    exc = RuntimeError(
        "dut not start: Unable to connect to port 22 on 10.0.0.1")

    assert is_testbed_unreachable_exception(exc)


def test_ignores_dut_not_start_after_successful_retry():
    exc = RuntimeError(
        "dut not start: DUT dut-1 did not startup at first try. "
        "res: {'state': 'started', 'port': 22}")

    assert not is_testbed_unreachable_exception(exc)


def test_detects_dut_did_not_startup_with_connectivity_failure():
    exc = RuntimeError(
        "DUT dut-1 did not startup: Timeout when waiting for port 22")

    assert is_testbed_unreachable_exception(exc)


def test_detects_dut_did_not_startup_after_reboot():
    exc = RuntimeError(
        "DUT dut-1 did not startup after reboot")

    assert is_testbed_unreachable_exception(exc)


def test_detects_sanity_recovery_connectivity_failure():
    exc = RuntimeError(
        "Recovery of sanity check failed: No route to host")

    assert is_testbed_unreachable_exception(exc)


def test_ignores_generic_timeout():
    assert not is_testbed_unreachable_exception(
        TimeoutError("test command timed out"))


def test_ignores_functional_did_not_startup_assertion():
    assert not is_testbed_unreachable_exception(
        AssertionError("DUT dut-1 did not startup"))


def test_ignores_non_matching_exception():
    node = _make_node()
    call = _make_call(AssertionError("expected 1, got 2"))

    assert not stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_not_called()
    assert not node.session.shouldstop


def test_ignores_sanity_recovery_without_connectivity_failure():
    assert not is_testbed_unreachable_exception(
        RuntimeError("Recovery of sanity check failed: invalid config"))


def test_ignores_connectivity_text_without_unhealthy_context():
    assert not is_testbed_unreachable_exception(
        RuntimeError("No route to host"))


def test_flags_cache_and_stops_session():
    node = _make_node()
    call = _make_call(RuntimeError(
        "dut not start: Unable to connect to port 22 on 10.0.0.1"))

    assert stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_called_once_with(
        DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, True)
    assert node.session.shouldstop == TESTBED_UNREACHABLE_STOP_REASON


def test_stops_when_cache_was_already_flagged():
    node = _make_node(cache_value=True)
    call = _make_call(RuntimeError(
        "Host unreachable in the inventory"))

    assert stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_not_called()
    assert node.session.shouldstop == TESTBED_UNREACHABLE_STOP_REASON


def test_includes_unreachable_host_names():
    node = _make_node()
    call = _make_call(FakeConnectionFailure(
        "Host unreachable",
        dark={"dut-1": {}, "dut-2": {}},
    ))

    assert stop_on_testbed_unreachable(
        node, call, FakeConnectionFailure)
    assert node.session.shouldstop.endswith("dut-1, dut-2")


def test_includes_host_name_from_exception_cause():
    node = _make_node()
    inner = FakeConnectionFailure(
        "connection detail", dark={"dut-1": {}})
    outer = RuntimeError()
    outer.__cause__ = inner
    call = _make_call(outer)

    assert stop_on_testbed_unreachable(
        node, call, FakeConnectionFailure)
    assert node.session.shouldstop.endswith("dut-1")


def test_preserves_existing_stop_reason():
    node = _make_node(shouldstop="existing reason")
    call = _make_call(RuntimeError(
        "Host unreachable in the inventory"))

    assert stop_on_testbed_unreachable(node, call)
    assert node.session.shouldstop == "existing reason"


def test_returns_false_without_exception():
    node = _make_node()

    assert not stop_on_testbed_unreachable(
        node, _make_call())
    node.config.cache.set.assert_not_called()
