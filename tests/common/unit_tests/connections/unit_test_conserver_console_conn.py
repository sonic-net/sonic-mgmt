"""Unit tests for the conserver console connection."""

from importlib import import_module, util
import os
from pathlib import Path
import sys
import types

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "connections"
    / "conserver_console_conn.py"
)
try:
    import_module("pexpect")
except ImportError:
    pexpect_stub = types.ModuleType("pexpect")
    pexpect_stub.TIMEOUT = type("TIMEOUT", (Exception,), {})
    pexpect_stub.EOF = type("EOF", (Exception,), {})
    sys.modules["pexpect"] = pexpect_stub
SPEC = util.spec_from_file_location(
    "unit_target_conserver_console_conn", MODULE_PATH
)
MODULE = util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ConserverConsoleConn = MODULE.ConserverConsoleConn


class FakeConsoleCli:
    """Record pexpect calls without opening a console connection."""

    linesep = b"\r\n"
    before = b"show output\r\nLINE_0000: output\r\n"

    def __init__(self):
        self.command = None
        self.expect_args = None

    def sendline(self, command):
        self.command = command

    def expect(self, pattern, timeout):
        self.expect_args = (pattern, timeout)


def make_connection():
    """Create a connection without invoking its I/O-heavy constructor."""
    connection = ConserverConsoleConn.__new__(ConserverConsoleConn)
    connection.console_cli = FakeConsoleCli()
    connection.logger = MODULE.logging.getLogger(__name__)
    connection.default_timeout = 30
    connection.delay_factor = 1
    return connection


def test_send_command_supports_netmiko_timeout_and_echo_arguments():
    """Use Netmiko-compatible arguments while preserving conserver output."""
    connection = make_connection()

    output = connection.send_command(
        "show output",
        expect_string=r"[#$]\s*$",
        read_timeout=300,
        cmd_verify=False,
    )

    assert connection.console_cli.command == "show output"
    assert connection.console_cli.expect_args == (r"[#$]\s*$", 300)
    assert output == "LINE_0000: output"


def test_send_command_keeps_max_loops_compatibility():
    """Retain the existing max_loops timeout behavior for current callers."""
    connection = make_connection()

    connection.send_command("show output", max_loops=60)

    assert connection.console_cli.expect_args == (
        "admin@[a-zA-Z0-9]{1,10}:~\\$",
        60,
    )


def test_sendline_with_timeout_writes_complete_line():
    """Write the complete command line when the pexpect child fd is writable."""
    read_fd, write_fd = os.pipe()
    connection = make_connection()
    connection.console_cli.child_fd = write_fd
    connection.console_cli.encoding = "utf-8"
    try:
        connection._sendline_with_timeout("show version", 1)
        os.close(write_fd)
        write_fd = None

        assert os.read(read_fd, 1024) == b"show version\r\n"
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def test_sendline_with_timeout_restores_blocking_mode_on_timeout():
    """Restore the pexpect fd blocking mode when a bounded write times out."""
    read_fd, write_fd = os.pipe()
    connection = make_connection()
    connection.console_cli.child_fd = write_fd
    try:
        assert os.get_blocking(write_fd) is True

        with pytest.raises(TimeoutError):
            connection._sendline_with_timeout("show version", 0)

        assert os.get_blocking(write_fd) is True
    finally:
        os.close(read_fd)
        os.close(write_fd)
