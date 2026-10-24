"""Reverse-SSH lifecycle regression tests without testbed dependencies.

Run with::

    pytest --noconftest --confcutdir=tests/common/unit_tests \
        -o log_format='%(message)s' tests/common/unit_tests/helpers/unit_test_console_helper.py

The real PTY cases require Linux, as does pexpect.spawn.
"""

import ast
from contextlib import contextmanager, ExitStack
import logging
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock, call

import pexpect
import pytest


TESTS_ROOT = Path(__file__).resolve().parents[3]
ESCAPE_CHARS = ["a", "b", "e", "f", "g", "k", "n", "p", "y"]


def _load_functions(path, names, namespace):
    """Load real functions without importing Ansible and testbed fixtures."""
    tree = ast.parse(path.read_text())
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in functions} == set(names)
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


@pytest.fixture
def disconnect():
    namespace = _load_functions(
        TESTS_ROOT / "common" / "helpers" / "console_helper.py",
        ["disconnect_console_client"],
        {"pexpect": pexpect, "logger": logging.getLogger(__name__)},
    )
    return namespace["disconnect_console_client"]


@pytest.fixture
def client():
    return Mock(closed=False)


@pytest.fixture
def cleanup_context():
    namespace = _load_functions(
        TESTS_ROOT / "common" / "helpers" / "console_helper.py",
        ["console_cleanup"],
        {"contextmanager": contextmanager, "ExitStack": ExitStack},
    )
    return namespace["console_cleanup"]


@pytest.mark.parametrize("escape_char", ESCAPE_CHARS)
def test_disconnect_drains_to_eof_before_closing(disconnect, client, escape_char):
    """Every supported escape waits for remote EOF before local cleanup."""
    disconnected = disconnect(client, escape_char, timeout_sec=7)
    expected_calls = [
        call.isalive(),
        call.sendcontrol(escape_char),
        call.sendcontrol("x"),
        call.expect(pexpect.EOF, timeout=7),
        call.close(force=True),
    ]
    assert disconnected
    assert client.mock_calls == expected_calls


def test_disconnect_accepts_absent_and_closed_clients(disconnect, client):
    """Best-effort shared cleanup remains safe for unused or closed clients."""
    disconnected = disconnect(None)
    assert disconnected
    client.closed = True
    disconnected = disconnect(client)
    assert disconnected
    assert client.mock_calls == []


def test_disconnect_reaps_already_exited_session(disconnect, client):
    """A force-interrupted session needs draining and reaping, not more input."""
    client.isalive.return_value = False
    disconnected = disconnect(client)
    assert disconnected
    client.sendcontrol.assert_not_called()
    client.expect.assert_called_once_with(pexpect.EOF, timeout=10)
    client.close.assert_called_once_with(force=True)


@pytest.mark.parametrize("operation,error", [
    ("expect", pexpect.TIMEOUT("output must not appear in the log")),
    ("sendcontrol", pexpect.EOF("output must not appear in the log")),
    ("sendcontrol", OSError("output must not appear in the log")),
])
def test_disconnect_reports_transport_failure_and_closes(disconnect, client, operation, error, caplog):
    """Forced local closure must not turn a failed escape into success."""
    getattr(client, operation).side_effect = error
    disconnected = disconnect(client)
    assert not disconnected
    client.close.assert_called_once_with(force=True)
    assert "Reverse SSH did not disconnect" in caplog.text
    assert "output must not appear" not in caplog.text


def test_disconnect_propagates_unexpected_error_after_closing(disconnect, client):
    """Do not silently swallow programming errors."""
    client.sendcontrol.side_effect = ValueError("invalid control")
    with pytest.raises(ValueError, match="invalid control"):
        disconnect(client)
    client.close.assert_called_once_with(force=True)


def test_disconnect_surfaces_local_cleanup_failure(disconnect, client):
    """A failure to close the owned process must remain visible."""
    client.close.side_effect = pexpect.ExceptionPexpect("could not terminate child")
    with pytest.raises(pexpect.ExceptionPexpect, match="could not terminate child"):
        disconnect(client)


@pytest.fixture
def session_factory(disconnect, client):
    finalizers = []
    namespace = _load_functions(
        TESTS_ROOT / "common" / "helpers" / "assertions.py",
        ["pytest_assert"],
        {"pytest": pytest},
    )
    namespace.update(
        pexpect=SimpleNamespace(spawn=Mock(return_value=client)),
        disconnect_console_client=disconnect,
        ensure_console_session_up=Mock(),
        wait_for_line_idle=Mock(),
    )
    _load_functions(
        TESTS_ROOT / "console" / "test_console_reversessh.py",
        ["console_session"],
        namespace,
    )
    create = namespace["console_session"].__wrapped__(
        "b", SimpleNamespace(addfinalizer=finalizers.append))
    return create, finalizers, namespace


def test_session_registers_cleanup_before_authentication(session_factory, client):
    """Cleanup is already registered when authentication starts."""
    create, finalizers, namespace = session_factory
    host = Mock()

    def check_cleanup_registered(*args, **kwargs):
        assert len(finalizers) == 1

    client.expect.side_effect = check_cleanup_registered
    created_client = create(host, "example.invalid", "user:0", "password", "0")
    assert created_client is client
    namespace["pexpect"].spawn.assert_called_once_with(
        "ssh user:0@example.invalid -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        echo=False,
    )
    finalizers[0]()
    client.sendcontrol.assert_has_calls([call("b"), call("x")])
    client.close.assert_called_once_with(force=True)
    namespace["wait_for_line_idle"].assert_called_once()


@pytest.mark.parametrize("failure_stage", ["authentication", "readiness"])
def test_session_setup_failure_closes_without_sending_escape(session_factory, client, failure_stage):
    """A partially established session is closed without claiming escape success."""
    create, finalizers, namespace = session_factory
    operation = client.expect if failure_stage == "authentication" else namespace["ensure_console_session_up"]
    operation.side_effect = pexpect.TIMEOUT("setup failed")
    with pytest.raises(pexpect.TIMEOUT, match="setup failed"):
        create(Mock(), "example.invalid", "user:0", "password", "0")
    finalizers[0]()
    client.close.assert_called_once_with(force=True)
    client.sendcontrol.assert_not_called()
    namespace["wait_for_line_idle"].assert_called_once()


def test_session_fails_graceful_disconnect_even_when_line_becomes_idle(session_factory, client):
    """The IDLE check must not hide forced local cleanup after an escape timeout."""
    create, finalizers, namespace = session_factory
    create(Mock(), "example.invalid", "user:0", "password", "0")
    client.expect.side_effect = pexpect.TIMEOUT("did not disconnect")
    with pytest.raises(pytest.fail.Exception, match="did not reach EOF after Ctrl-B Ctrl-X"):
        finalizers[0]()
    client.close.assert_called_once_with(force=True)
    namespace["wait_for_line_idle"].assert_called_once()


def test_sessions_have_independent_finalizers(session_factory, client):
    """One failed disconnect cannot prevent pytest from cleaning up another client."""
    create, finalizers, namespace = session_factory
    other = Mock(closed=False)
    namespace["pexpect"].spawn.side_effect = [client, other]
    create(Mock(), "example.invalid", "user:0", "password", "0")
    create(Mock(), "example.invalid", "user:1", "password", "1")
    assert len(finalizers) == 2
    other.expect.side_effect = pexpect.TIMEOUT("did not disconnect")
    with pytest.raises(pytest.fail.Exception):
        finalizers[1]()
    finalizers[0]()
    other.close.assert_called_once_with(force=True)
    client.close.assert_called_once_with(force=True)
    assert namespace["wait_for_line_idle"].call_count == 2


def _cleanup_block(filename, function_name):
    """Extract the real finally block without running hardware setup."""
    path = TESTS_ROOT / "console" / filename
    tree = ast.parse(path.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function_name)
    cleanup = next(node.finalbody for node in function.body if isinstance(node, ast.Try) and node.finalbody)
    return compile(ast.Module(body=cleanup, type_ignores=[]), str(path), "exec")


def test_cleanup_runs_in_reverse_registration_order(cleanup_context):
    """Successful cleanup executes every callback once, with its arguments."""
    operations = Mock()
    with cleanup_context() as cleanup:
        cleanup(operations.restore, "line", mode="original")
        cleanup(operations.disconnect, "client")
        operations.restore.assert_not_called()
        operations.disconnect.assert_not_called()
    expected_calls = [
        call.disconnect("client"),
        call.restore("line", mode="original"),
    ]
    assert operations.mock_calls == expected_calls


def test_cleanup_preserves_body_and_multiple_callback_failures(cleanup_context):
    """A final failure retains the original body and earlier cleanup exceptions."""
    body_error = ValueError("body failed")
    first_error = OSError("first cleanup failed")
    last_error = RuntimeError("last cleanup failed")
    first = Mock(side_effect=first_error)
    last = Mock(side_effect=last_error)
    with pytest.raises(RuntimeError) as raised:
        with cleanup_context() as cleanup:
            cleanup(last)
            cleanup(first)
            raise body_error
    assert raised.value is last_error
    assert last_error.__context__ is first_error
    assert first_error.__context__ is body_error
    first.assert_called_once_with()
    last.assert_called_once_with()


@pytest.mark.parametrize("filename,function_name,same_host", [
    ("test_console_loopback.py", "test_console_loopback_echo", False),
    ("test_console_loopback.py", "test_console_loopback_echo", True),
    ("test_console_loopback.py", "test_console_loopback_pingpong", False),
    ("test_console_link_wiring.py", "_verify_one_line", False),
    ("test_console_link_wiring.py", "_verify_one_line", True),
])
@pytest.mark.parametrize("idle_failure", [False, True])
def test_consumer_close_failure_preserves_independent_cleanup(
        disconnect, cleanup_context, filename, function_name, same_host, idle_failure):
    """Close and IDLE failures must not skip peers, unbridging or config restoration."""
    first = Mock(closed=False)
    second = Mock(closed=False)
    close_error = pexpect.ExceptionPexpect("could not terminate child")
    first.close.side_effect = close_error
    host = Mock()
    fanout = host if same_host else Mock()
    idle = Mock()
    if idle_failure:
        idle.side_effect = [pytest.fail.Exception("line still busy"), None]
    configure = Mock()
    namespace = dict(
        console_cleanup=cleanup_context, disconnect_console_client=disconnect,
        wait_for_line_idle=idle, configure_console_line=configure,
        duthost=host, console_fanout=fanout, same_host=same_host,
        client=first, sender=first, receiver=second, dut_client=first, fanout_client=second,
        target_line="0", src_line="0", dst_line="1", fanout_line="2",
        fanout_src_line="2", fanout_dst_line="3",
        orig_baud="9600", orig_flow_control="disable",
        orig_src_baud="9600", orig_src_flow_control="disable",
        orig_dst_baud="115200", orig_dst_flow_control="enable",
    )
    expected_error = pytest.fail.Exception if idle_failure else pexpect.ExceptionPexpect
    with pytest.raises(expected_error) as raised:
        exec(_cleanup_block(filename, function_name), namespace)
    error = raised.value
    while error is not close_error and error.__context__ is not None:
        error = error.__context__
    assert error is close_error
    first.close.assert_called_once_with(force=True)
    two_clients = function_name.endswith("pingpong") or (function_name == "_verify_one_line" and not same_host)
    if two_clients:
        second.close.assert_called_once_with(force=True)
    else:
        second.close.assert_not_called()
    assert idle.call_count == (2 if two_clients else 1)
    if function_name.endswith("echo"):
        if not same_host:
            fanout.unset_loopback.assert_called_once_with("2")
        configure.assert_called_once_with(host, "0", "9600", "disable")
    elif function_name.endswith("pingpong"):
        fanout.unbridge.assert_called_once_with("2", "3")
        expected_calls = [
            call(host, "0", "9600", "disable"),
            call(host, "1", "115200", "enable"),
        ]
        assert configure.call_args_list == expected_calls
    else:
        assert idle.call_args_list[0].args == (host, "0")
        if not same_host:
            assert idle.call_args_list[1].args == (fanout, "0")


@pytest.mark.parametrize("failure_mode", ["close", "escape"])
def test_mirror_disconnect_failure_is_reported_after_other_cleanup(disconnect, failure_mode):
    """Mirror teardown must process remaining clients and recordings before failing."""
    path = TESTS_ROOT / "console" / "test_console_mirror.py"
    tree = ast.parse(path.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "mirror_test_context")
    yield_index = next(i for i, node in enumerate(function.body)
                       if isinstance(node, ast.Expr) and isinstance(node.value, ast.Yield))
    cleanup = compile(ast.Module(body=function.body[yield_index + 1:], type_ignores=[]), str(path), "exec")
    first = Mock(closed=False)
    second = Mock(closed=False)
    if failure_mode == "close":
        first.close.side_effect = pexpect.ExceptionPexpect("could not terminate child")
    else:
        first.expect.side_effect = pexpect.TIMEOUT("escape timed out")
    host = Mock()
    context = SimpleNamespace(clients=[first, second], recording_prefixes={"recording"})
    wait = Mock(return_value=True)
    remove = Mock()
    namespace = dict(
        pytest=pytest, context=context, duthost=host, line="0",
        disconnect_console_client=disconnect,
        _get_cli_status=Mock(return_value={"state": "idle"}),
        _get_state_db=Mock(return_value={"state": "idle"}),
        _wait_for_mirror_idle=Mock(return_value=True),
        MIRROR_ACTIVE_FIELDS=set(), _recording_is_open=Mock(return_value=False),
        wait_until=wait, check_target_line_status=Mock(),
        _remove_test_recording=remove,
    )
    expected = "could not terminate child" if failure_mode == "close" else "did not disconnect gracefully"
    with pytest.raises(pytest.fail.Exception, match=expected):
        exec(cleanup, namespace)
    first.close.assert_called_once_with(force=True)
    second.close.assert_called_once_with(force=True)
    wait.assert_called_once_with(15, 1, 0, namespace["check_target_line_status"], host, "0", "IDLE")
    remove.assert_called_once_with(host, "recording")


@pytest.mark.skipif(os.name != "posix", reason="pexpect.spawn requires a POSIX PTY")
@pytest.mark.parametrize("escape_char", ESCAPE_CHARS)
def test_disconnect_drains_real_pty_output(disconnect, escape_char):
    """A child blocked on console output must receive escape and exit before close."""
    script = """
import os
import sys
import tty
tty.setraw(0)
os.write(1, b"connected\\n")
pending = b"." * (256 * 1024)
while pending:
    pending = pending[os.write(1, pending):]
received = b""
while len(received) < 2:
    received += os.read(0, 2 - len(received))
sys.exit(0 if received == bytes([int(sys.argv[1]), 24]) else 1)
"""
    child = pexpect.spawn(sys.executable, ["-c", script, str(ord(escape_char) - 96)], echo=False)
    try:
        child.expect_exact("connected")
        disconnected = disconnect(child, escape_char)
        assert disconnected
        assert child.closed
        assert child.exitstatus == 0
        assert child.signalstatus is None
    finally:
        child.close(force=True)


@pytest.mark.skipif(os.name != "posix", reason="pexpect.spawn requires a POSIX PTY")
def test_disconnect_closes_real_child_that_ignores_escape(disconnect):
    """A stubborn child is reaped, but its failed graceful exit stays a failure."""
    script = """
import os
import time
import tty
tty.setraw(0)
os.write(1, b"connected\\n")
time.sleep(60)
"""
    child = pexpect.spawn(sys.executable, ["-c", script], echo=False)
    try:
        child.expect_exact("connected")
        disconnected = disconnect(child, timeout_sec=0.1)
        assert not disconnected
        assert child.closed
        alive = child.isalive()
        assert not alive
    finally:
        child.close(force=True)
