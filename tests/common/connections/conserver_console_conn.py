import logging
import pexpect
import os
import time

# Absolute import: the unit tests load this file on its own, outside its package.
from tests.common.connections.pexpect_console_conn import PexpectConsoleConn

CONSERVER_CLI_PROMPT = "admin@[a-zA-Z0-9]{1,10}:~\\$"
CONSERVER_DEBUG_FILE = "/tmp/conserver_console_debug.log"
LOGIN_USERNAME_PATTERN = "login"
LOGIN_PWD_PATTERN = "Password:"
# The login at connect waits up to DEFAULT_TIMEOUT_S for each prompt. send_command() and
# read_until_pattern() wait up to read_timeout (DEFAULT_TIMEOUT_S by default), and
# send_command() waits max_loops * delay_factor seconds instead if that is longer
# (delay_factor is DEFAULT_DELAY_FACTOR by default). send_command_timing() reads until
# the line is quiet for last_read (DEFAULT_LAST_READ_S by default), up to read_timeout
# (DEFAULT_TIMEOUT_S by default).
DEFAULT_DELAY_FACTOR = 1
DEFAULT_TIMEOUT_S = 30
DEFAULT_LAST_READ_S = 1.0


class ConserverConsoleConn(PexpectConsoleConn):
    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)

        if "console_device" not in kwargs and "console_port" not in kwargs:
            raise ValueError("Either console_device or console_port is not set")

        self.sonic_username = kwargs['sonic_username']
        self.sonic_password = kwargs['sonic_password'][0]
        self.console_type = kwargs['console_type']
        conserver_info = kwargs['console_device'].split(":")
        self.conserver_host = conserver_info[0]
        self.conserver_name = conserver_info[1]
        self.device_type = "_conserver"
        self.port = kwargs['console_port']
        self.delay_factor = DEFAULT_DELAY_FACTOR
        self.default_timeout = DEFAULT_TIMEOUT_S
        self.connect(kwargs.get("timeout_s"))

    def _connect(self):
        console_cli = self._spawn(
            'console', ["-f", "-M", self.conserver_host,
                        self.conserver_name, "-p", self.port],
            timeout=self.default_timeout)

        if os.path.exists(CONSERVER_DEBUG_FILE):
            os.remove(CONSERVER_DEBUG_FILE)
        console_cli.logfile = open(CONSERVER_DEBUG_FILE, "wb")

        console_cli.sendline()
        match = console_cli.expect([LOGIN_USERNAME_PATTERN, CONSERVER_CLI_PROMPT])
        if match == 0:
            console_cli.sendline(self.sonic_username)
            console_cli.expect(LOGIN_PWD_PATTERN)
            console_cli.sendline(self.sonic_password)
            console_cli.expect(CONSERVER_CLI_PROMPT)

        self.console_cli = console_cli

    def send_command(
        self,
        cmd,
        expect_string=CONSERVER_CLI_PROMPT,
        max_loops=None,
        read_timeout=None,
        cmd_verify=True,
    ):
        """Send a command using Netmiko-compatible arguments.

        Conserver does not perform command echo verification, so cmd_verify is
        accepted for interface compatibility only.
        """
        self.console_cli.sendline(cmd)
        timeout = (
            read_timeout if read_timeout is not None else self.default_timeout
        )
        if max_loops:
            timeout = max(max_loops * self.delay_factor, timeout)
        self.console_cli.expect(expect_string, timeout=timeout)
        output = self.console_cli.before.decode()
        return output.split(self.console_cli.linesep.decode(), 1)[1].strip()

    def write_channel(self, cmd, add_newline=True):
        if add_newline:
            self.console_cli.sendline(cmd)
        else:
            self.console_cli.send(cmd)

    def read_until_pattern(self, pattern, read_timeout=None):
        timeout = read_timeout if read_timeout is not None else self.default_timeout
        self.console_cli.expect(pattern, timeout=timeout)

    def _graceful_disconnect(self):
        """Run by disconnect(graceful=True): the disconnect() this class had before, unchanged."""
        assert self.console_cli.isalive()
        self.console_cli.sendline('\x05c.')
        self.console_cli.close(force=True)
        self.logger.debug("Conserver connection closed.")

    def send_command_timing(self, cmd, read_timeout=DEFAULT_TIMEOUT_S, last_read=DEFAULT_LAST_READ_S):
        """Send command and read output until no data for 'last_read' seconds."""
        self.logger.debug("send_command_timing: cmd='%s'", cmd[:80])

        start_time = time.monotonic()
        self.console_cli.sendline(cmd)

        output = ""
        deadline = start_time + read_timeout

        while time.monotonic() < deadline:
            try:
                self.console_cli.expect(r'.+', timeout=last_read)
                output += self.console_cli.match.group().decode()
            except pexpect.TIMEOUT:
                break
            except pexpect.EOF:
                self.logger.warning("send_command_timing: connection closed")
                break

        elapsed = time.monotonic() - start_time
        self.logger.debug("send_command_timing: finished in %.1fs, %d bytes collected",
                          elapsed, len(output))
        return output
