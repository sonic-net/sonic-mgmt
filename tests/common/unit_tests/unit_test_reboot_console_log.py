"""
Unit tests for the reboot console-log collector: tests/common/reboot.py and the
attach-only console it uses (tests/common/connections/ssh_console_conn.py).

The collector attaches to the DUT console line without logging in to the DUT, so
it never writes to the line and cannot interrupt a bootloader autoboot countdown.

Follows the repo unit-test convention (unit_test_*.py, run with --noconftest).
"""

import collections
import importlib
import os
import sys
import threading
from unittest import mock

import pytest

# Make the repo root importable so ``tests.common.reboot`` resolves regardless of
# the pytest invocation directory. Mirrors the existing repo unit-test convention.
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_TEST_DIR)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.connections.base_console_conn import CONSOLE_SSH_MENU_PORTS  # noqa: E402
from tests.common.connections.ssh_console_conn import SSHConsoleConn  # noqa: E402

# tests.common exports a reboot() function, so import the module by its full name.
reboot = importlib.import_module("tests.common.reboot")


def _make_attach_only_console(read_chunks):
    """An attach-only SSHConsoleConn with a mocked console line; __new__ bypasses the
    network-connecting __init__."""
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.attach_only = True
    conn.console_type = "console_ssh"
    conn.menu_port = None
    conn.username = "console_user:7001"
    conn.logger = mock.MagicMock()
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    conn.write_channel = mock.MagicMock()
    queue = collections.deque(read_chunks)
    conn.read_channel = mock.MagicMock(side_effect=lambda: queue.popleft() if queue else "")
    return conn


def test_attach_only_session_preparation_writes_nothing():
    conn = _make_attach_only_console(["sonic login: \n"])
    conn.login_stage_2 = mock.MagicMock()
    conn._recover_to_login_prompt = mock.MagicMock()
    conn.session_preparation_finalise = mock.MagicMock()

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        SSHConsoleConn.session_preparation(conn)

    conn.write_channel.assert_not_called()
    conn.login_stage_2.assert_not_called()
    conn._recover_to_login_prompt.assert_not_called()
    conn.session_preparation_finalise.assert_not_called()


def test_attach_only_cleanup_closes_without_probing():
    conn = _make_attach_only_console([])
    conn.send_command = mock.MagicMock()
    conn._is_at_sonic_prompt = mock.MagicMock()
    rc = conn.remote_conn = mock.MagicMock()

    SSHConsoleConn.cleanup(conn)

    conn._is_at_sonic_prompt.assert_not_called()
    conn.send_command.assert_not_called()
    conn.write_channel.assert_not_called()
    rc.close.assert_called_once()


def test_attach_only_rejects_menu_port_console():
    with pytest.raises(ValueError):
        SSHConsoleConn(console_type=CONSOLE_SSH_MENU_PORTS, attach_only=True, console_host="10.0.0.1",
                       console_port="7", console_username="cadmin", console_password=["cpassword"],
                       sonic_username=None, sonic_password=None)


def test_console_attached_after_reboot_started_is_closed():
    """A console that attaches after the reboot started must not stay on the
    console line while the DUT boots."""
    cancel_event = threading.Event()
    console = mock.MagicMock()

    def attach(*args, **kwargs):
        cancel_event.set()  # the reboot starts while the console is attaching
        return console

    with mock.patch.object(reboot, "logger"), \
            mock.patch.object(reboot, "get_graph_facts"), \
            mock.patch.object(reboot, "attach_duthost_console", side_effect=attach):
        result = reboot.collect_console_log(mock.MagicMock(), mock.MagicMock(), cancel_event=cancel_event)

    assert result is None
    console.disconnect.assert_called_once()


def test_console_log_reader_logs_output_and_disconnects():
    console = mock.MagicMock()
    console.read_channel.side_effect = ["U-Boot 2013.01\r\n\r\nHit any key to stop autoboot:  2"] + [""] * 10

    with mock.patch.object(reboot.logger, "info") as info:
        reader = reboot.ConsoleLogReader(console)
        reader.stop()

    logged = [c.args[0] for c in info.call_args_list]
    assert "DUT console: U-Boot 2013.01" in logged
    assert "DUT console: Hit any key to stop autoboot:  2" in logged
    assert "DUT console: " not in logged
    console.disconnect.assert_called_once()
    console.write_channel.assert_not_called()
