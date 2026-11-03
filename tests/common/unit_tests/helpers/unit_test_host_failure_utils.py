"""Unit tests for host failure detection helpers."""

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
MAX_INSPECTED_MESSAGE_LENGTH = (
    HOST_FAILURE_UTILS.MAX_INSPECTED_MESSAGE_LENGTH
)
is_testbed_unreachable_exception = (
    HOST_FAILURE_UTILS.is_testbed_unreachable_exception
)
stop_on_testbed_unreachable = (
    HOST_FAILURE_UTILS.stop_on_testbed_unreachable
)


class FakeConnectionFailure(Exception):
    """Represent a pytest-ansible connection failure in unit tests."""

    def __init__(self, message, dark=None):
        super().__init__(message)
        self.dark = dark


class FakeCoreConnectionFailure(Exception):
    """Represent an ansible-core connection failure in unit tests."""

    pass


class FakeExceptionGroup(Exception):
    """Stand-in for ExceptionGroup, which needs python 3.11 or newer."""

    def __init__(self, message, exceptions):
        super().__init__(message)
        self.exceptions = exceptions


def _make_node(cache_value=None, shouldstop=False):
    """Create a minimal pytest node with cache and session state."""
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
    """Create a minimal pytest call object."""
    excinfo = None if exc is None else SimpleNamespace(value=exc)
    return SimpleNamespace(excinfo=excinfo, when=when)


def test_detects_ansible_connection_failure_with_unreachable_hosts():
    """Detect connection failures that include unreachable hosts."""
    exc = FakeConnectionFailure("connection detail", dark={"dut-1": {}})

    assert is_testbed_unreachable_exception(
        exc, FakeConnectionFailure)


def test_ignores_connection_failure_type_without_unreachable_hosts():
    """Ignore connection failure types without unreachable-host evidence."""
    # ansible-core raises the same exception type for a dropped ssh session.
    exc = FakeConnectionFailure("authentication detail")

    assert not is_testbed_unreachable_exception(
        exc, FakeConnectionFailure)


def test_ignores_core_connection_failure_without_evidence():
    """Ignore ansible-core connection failures without unreachable evidence."""
    exc = FakeCoreConnectionFailure("connection detail")

    assert not is_testbed_unreachable_exception(
        exc, (FakeConnectionFailure, FakeCoreConnectionFailure))


def test_detects_connection_failure_type_tuple():
    """Accept a tuple of supported connection failure types."""
    exc = FakeConnectionFailure("connection detail", dark={"dut-1": {}})

    assert is_testbed_unreachable_exception(
        exc, (FakeConnectionFailure, FakeCoreConnectionFailure))


def test_detects_wrapped_host_unreachable():
    """Detect a wrapped pytest-ansible inventory failure message."""
    exc = RuntimeError(
        "Thread worker aborted: Host unreachable in the inventory")

    assert is_testbed_unreachable_exception(exc)


def test_detects_wrapped_host_unreachable_in_extra_inventory():
    """Treat a wrapped extra-inventory failure as a testbed failure."""
    # pytest-ansible raises a second, differently worded message when the
    # unreachable host comes from the extra inventory.
    exc = RuntimeError(
        "Thread worker aborted: Host unreachable in the extra inventory")

    assert is_testbed_unreachable_exception(exc)


def test_detects_host_unreachable_when_upstream_says_hosts():
    """Keep detection stable if upstream pluralizes the leading noun."""
    # The marker omits the leading noun so a "Host" -> "Hosts" rename upstream
    # cannot silently disable the wrapped-exception detection.
    exc = RuntimeError("Hosts unreachable in the inventory")

    assert is_testbed_unreachable_exception(exc)


def test_detects_host_unreachable_without_connection_failure_types():
    """Detect the inventory marker without configured exception types."""
    exc = FakeConnectionFailure("Host unreachable in the inventory")

    assert is_testbed_unreachable_exception(exc)


def test_detects_connection_failure_in_exception_cause():
    """Detect unreachable evidence in an exception cause."""
    inner = FakeConnectionFailure(
        "connection detail", dark={"dut-1": {}})
    outer = RuntimeError()
    outer.__cause__ = inner

    assert is_testbed_unreachable_exception(
        outer, FakeConnectionFailure)


def test_detects_connection_failure_in_exception_context():
    """Detect unreachable evidence in an exception context."""
    inner = RuntimeError("Host unreachable in the inventory")
    outer = RuntimeError("wrapper")
    outer.__context__ = inner

    assert is_testbed_unreachable_exception(outer)


def test_ignores_suppressed_exception_context():
    """Ignore exception context suppressed with raise-from-None semantics."""
    # "raise ... from None" means the context is not relevant to the failure.
    inner = RuntimeError("Host unreachable in the inventory")
    outer = RuntimeError("wrapper")
    outer.__context__ = inner
    outer.__suppress_context__ = True

    assert not is_testbed_unreachable_exception(outer)


def test_detects_connection_failure_in_exception_group():
    """Detect unreachable evidence nested in an exception group."""
    group = FakeExceptionGroup(
        "parallel fixture failed",
        [FakeConnectionFailure("connection detail", dark={"dut-1": {}})],
    )

    assert is_testbed_unreachable_exception(
        group, FakeConnectionFailure)


def test_detects_dut_not_start_connectivity_failure():
    """Detect a DUT startup failure with SSH connectivity evidence."""
    exc = RuntimeError(
        "dut not start: Unable to connect to port 22 on 10.0.0.1")

    assert is_testbed_unreachable_exception(exc)


def test_ignores_dut_not_start_after_successful_retry():
    """Ignore an initial DUT startup miss followed by a successful retry."""
    exc = RuntimeError(
        "dut not start: DUT dut-1 did not startup at first try. "
        "res: {'state': 'started', 'port': 22}")

    assert not is_testbed_unreachable_exception(exc)


def test_detects_dut_did_not_startup_with_connectivity_failure():
    """Detect a DUT startup timeout that leaves the testbed unusable."""
    exc = RuntimeError(
        "DUT dut-1 did not startup: Timeout when waiting for port 22")

    assert is_testbed_unreachable_exception(exc)


def test_detects_dut_did_not_startup_after_reboot():
    """Detect a DUT that never returns after reboot."""
    exc = RuntimeError(
        "DUT dut-1 did not startup after reboot")

    assert is_testbed_unreachable_exception(exc)


def test_detects_sanity_recovery_connectivity_failure():
    """Detect connectivity failure while recovering a sanity check."""
    exc = RuntimeError(
        "Recovery of sanity check failed: No route to host")

    assert is_testbed_unreachable_exception(exc)


def test_ignores_generic_timeout():
    """Ignore generic timeouts without testbed-failure context."""
    assert not is_testbed_unreachable_exception(
        TimeoutError("test command timed out"))


def test_ignores_functional_did_not_startup_assertion():
    """Ignore functional startup assertions without connectivity evidence."""
    assert not is_testbed_unreachable_exception(
        AssertionError("DUT dut-1 did not startup"))


def test_ignores_sanity_recovery_without_connectivity_failure():
    """Ignore sanity recovery failures unrelated to connectivity."""
    assert not is_testbed_unreachable_exception(
        RuntimeError("Recovery of sanity check failed: invalid config"))


def test_ignores_connectivity_text_without_unhealthy_context():
    """Ignore connectivity text without a DUT or recovery context."""
    assert not is_testbed_unreachable_exception(
        RuntimeError("No route to host"))


def test_ignores_marker_beyond_inspected_message_length():
    """Ignore unreachable markers beyond the bounded message prefix."""
    padding = "a" * MAX_INSPECTED_MESSAGE_LENGTH
    exc = RuntimeError(padding + " Host unreachable in the inventory")

    assert not is_testbed_unreachable_exception(exc)


def test_ignores_ping_output_reporting_destination_host_unreachable():
    """Ignore ICMP destination-unreachable text from an auxiliary peer."""
    # tacacs_helper.setup_tacacs_client embeds raw ping stdout in its failure
    # message, an unreachable ping peer must not retire a healthy DUT.
    exc = AssertionError(
        "TACACS server not reachable: "
        "PING 10.250.0.101 (10.250.0.101) 56(84) bytes of data.\n"
        "From 10.250.0.1 icmp_seq=1 Destination Host Unreachable\n"
        "1 packets transmitted, 0 received, +1 errors, 100% packet loss")

    assert not is_testbed_unreachable_exception(exc)


def test_ignores_non_matching_exception():
    """Leave session state unchanged for unrelated test failures."""
    node = _make_node()
    call = _make_call(AssertionError("expected 1, got 2"))

    assert not stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_not_called()
    assert not node.session.shouldstop


def test_flags_cache_and_stops_session():
    """Set the host-failure flag and stop reason after detection."""
    node = _make_node()
    call = _make_call(RuntimeError(
        "dut not start: Unable to connect to port 22 on 10.0.0.1"))

    assert stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_called_once_with(
        DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, True)
    assert node.session.shouldstop == TESTBED_UNREACHABLE_STOP_REASON


def test_flags_cache_even_when_stale_flag_was_left_behind():
    """Rewrite the host-failure flag even when the cache already has it."""
    node = _make_node(cache_value=True)
    call = _make_call(RuntimeError(
        "Host unreachable in the inventory"))

    assert stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_called_once_with(
        DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, True)
    assert node.session.shouldstop == TESTBED_UNREACHABLE_STOP_REASON


def test_includes_unreachable_host_names_in_stable_order():
    """Include sorted unreachable host names in the stop reason."""
    node = _make_node()
    call = _make_call(FakeConnectionFailure(
        "Host unreachable",
        dark={"dut-2": {}, "dut-1": {}},
    ))

    assert stop_on_testbed_unreachable(
        node, call, FakeConnectionFailure)
    assert node.session.shouldstop.endswith("dut-1, dut-2")


def test_includes_host_name_from_exception_cause():
    """Include a host name found in a nested exception cause."""
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
    """Preserve a stop reason set by another pytest component."""
    node = _make_node(shouldstop="existing reason")
    call = _make_call(RuntimeError(
        "Host unreachable in the inventory"))

    assert stop_on_testbed_unreachable(node, call)
    node.config.cache.set.assert_called_once_with(
        DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, True)
    assert node.session.shouldstop == "existing reason"


def test_logs_once_per_session():
    """Log only the first detected testbed failure in a session."""
    node = _make_node()
    exc = RuntimeError("Host unreachable in the inventory")

    assert stop_on_testbed_unreachable(node, _make_call(exc, when="setup"))
    logged_after_first = HOST_FAILURE_UTILS.logger.error.call_count

    assert stop_on_testbed_unreachable(node, _make_call(exc, when="teardown"))
    assert HOST_FAILURE_UTILS.logger.error.call_count == logged_after_first


def test_returns_false_without_exception():
    """Do nothing when the pytest phase completed without an exception."""
    node = _make_node()

    assert not stop_on_testbed_unreachable(
        node, _make_call())
    node.config.cache.set.assert_not_called()
