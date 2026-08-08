"""Unit tests for the linecard console connection."""

from importlib import import_module, util
from pathlib import Path
import sys
import types


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "connections"
    / "linecard_console_conn.py"
)
try:
    import_module("pexpect")
except ImportError:
    pexpect_stub = types.ModuleType("pexpect")
    pexpect_stub.TIMEOUT = type("TIMEOUT", (Exception,), {})
    pexpect_stub.EOF = type("EOF", (Exception,), {})
    sys.modules["pexpect"] = pexpect_stub
SPEC = util.spec_from_file_location(
    "unit_target_linecard_console_conn", MODULE_PATH
)
MODULE = util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
LinecardConsoleConn = MODULE.LinecardConsoleConn


class FakeMatch:
    """Return one chunk from a pexpect match."""

    def __init__(self, output):
        self.output = output

    def group(self):
        return self.output


class FakeConsoleCli:
    """Record pexpect calls without opening a console connection."""

    linesep = b"\r\n"
    before = b"show output\r\nLINE_0000: output\r\n"

    def __init__(self, timing_output=None):
        self.command = None
        self.expect_args = None
        self.timing_output = timing_output
        self.match = None

    def sendline(self, command):
        self.command = command

    def expect(self, pattern, timeout):
        self.expect_args = (pattern, timeout)
        if pattern == r'.+':
            if self.timing_output is None:
                raise MODULE.pexpect.TIMEOUT("timed out")
            self.match = FakeMatch(self.timing_output)
            self.timing_output = None


def make_connection(timing_output=None):
    """Create a connection without invoking its I/O-heavy constructor."""
    connection = LinecardConsoleConn.__new__(LinecardConsoleConn)
    connection.logger = MODULE.logging.getLogger(__name__)
    connection.console_cli = FakeConsoleCli(timing_output)
    connection.default_timeout = 30
    connection.delay_factor = 1
    return connection


def test_send_command_supports_netmiko_timeout_and_echo_arguments():
    """Use Netmiko-compatible arguments while preserving linecard output."""
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


def test_send_command_timing_supports_large_input_check():
    """Provide the timing API used by the console stress input test."""
    connection = make_connection(b"echo\r\nexpected-md5  -\r\n")

    output = connection.send_command_timing(
        "echo large-input | md5sum",
        read_timeout=300,
        last_read=2.0,
    )

    assert connection.console_cli.command == "echo large-input | md5sum"
    assert "expected-md5" in output
