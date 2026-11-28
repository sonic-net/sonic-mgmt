import logging
import pexpect
import os
import time

# Absolute import: the unit tests load this file on its own, outside its package.
from tests.common.connections.pexpect_console_conn import PexpectConsoleConn

LINECARD_CLI_PROMPT = r"admin@[a-zA-Z0-9\-]{1,20}:~\$"
LINECARD_DEBUG_FILE = "/tmp/linecard_console_debug.log"
LOGIN_USERNAME_PATTERN = "login:"
LOGIN_PWD_PATTERN = "[Pp]assword:"
LOGIN_FAILURE_PATTERN = "Login incorrect"
PICOCOM_READY_PATTERN = "Terminal ready"
PICOCOM_EXIT_PATTERN = "Thanks for using picocom"
# How the connect workflow uses the timeouts below.
#   a. SSH to the supervisor and log in, waiting up to DEFAULT_TIMEOUT_S for each prompt.
#   b. Kill any picocom left running and wait up to PICOCOM_KILL_TIMEOUT_S for the shell
#      prompt; if it does not come, send a newline and wait once more.
#   c. Start picocom on the linecard's serial port and wait up to PICOCOM_READY_TIMEOUT_S
#      for "Terminal ready".
#   d. Send a newline and wait up to LOGIN_USERNAME_TIMEOUT_S for a login or shell prompt.
#      At a login prompt, send the username, wait up to LOGIN_PWD_TIMEOUT_S for the
#      password prompt, send the password, then wait up to LOGIN_RESULT_TIMEOUT_S for the
#      shell prompt or a login failure.
# disconnect() exits picocom and waits up to PICOCOM_EXIT_TIMEOUT_S for it to finish.
# send_command() and read_until_pattern() wait up to read_timeout (DEFAULT_TIMEOUT_S by
# default), and send_command() waits max_loops * delay_factor seconds instead if that is
# longer (delay_factor is DEFAULT_DELAY_FACTOR by default). send_command_timing() reads
# until the line is quiet for last_read (DEFAULT_LAST_READ_S by default), up to
# read_timeout (DEFAULT_TIMEOUT_S by default).
DEFAULT_DELAY_FACTOR = 1
DEFAULT_TIMEOUT_S = 30
DEFAULT_LAST_READ_S = 1.0
PICOCOM_KILL_TIMEOUT_S = 5
PICOCOM_READY_TIMEOUT_S = 20
LOGIN_USERNAME_TIMEOUT_S = 20
LOGIN_PWD_TIMEOUT_S = 10
LOGIN_RESULT_TIMEOUT_S = 30
PICOCOM_EXIT_TIMEOUT_S = 20


class UnsupportedPlatformError(Exception):
    """Exception raised when the platform/hwsku is not supported for linecard console access."""
    pass


class LinecardConsoleConn(PexpectConsoleConn):
    """
    Console connection wrapper for linecard consoles accessed via picocom on supervisor.

    This class provides a connection to linecard consoles on modular chassis systems
    (currently Arista only) by:
    1. SSH to the supervisor node
    2. Launching picocom to connect to the linecard serial port
    3. Authenticating to the linecard
    """

    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        self.delay_factor = DEFAULT_DELAY_FACTOR
        self.default_timeout = DEFAULT_TIMEOUT_S

        # Validate hwsku FIRST before doing anything else
        hwsku = kwargs.get('hwsku', '').lower()
        if 'arista' not in hwsku:
            raise UnsupportedPlatformError(
                f"Unsupported hwsku: {hwsku}. Only Arista chassis is supported."
            )

        # Validate required parameters
        required_params = ['supervisor_ip', 'slot_num', 'sonic_username', 'sonic_password']
        for param in required_params:
            if param not in kwargs:
                raise ValueError(f"Required parameter '{param}' is not set")

        # Extract parameters
        self.supervisor_ip = kwargs['supervisor_ip']
        self.sonic_username = kwargs['sonic_username']
        self.sonic_password = (kwargs['sonic_password'][0] if isinstance(kwargs['sonic_password'], list)
                               else kwargs['sonic_password'])
        slot_num = kwargs['slot_num']

        # Platform-specific slot conversion (Arista: slot3 -> SCD0, slot7 -> SCD4)
        self.linecard_number = str(int(slot_num[len("slot"):]) - 3)
        self.connect(kwargs.get("timeout_s"))

    def _connect(self):
        # SSH to supervisor
        ssh_cmd = (f'ssh {self.sonic_username}@{self.supervisor_ip} '
                   '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null')
        self.logger.debug(f"Connecting to supervisor at {self.supervisor_ip}")

        console_cli = self._spawn(ssh_cmd, timeout=self.default_timeout, echo=False)

        # Set up debug logging
        if os.path.exists(LINECARD_DEBUG_FILE):
            os.remove(LINECARD_DEBUG_FILE)
        console_cli.logfile = open(LINECARD_DEBUG_FILE, "wb")

        # Authenticate to supervisor
        console_cli.expect(LOGIN_PWD_PATTERN)
        console_cli.sendline(self.sonic_password)
        console_cli.expect(LINECARD_CLI_PROMPT)

        # Kill any existing picocom sessions
        console_cli.sendline('sudo pkill -9 picocom || true')
        try:
            console_cli.expect(LINECARD_CLI_PROMPT, timeout=PICOCOM_KILL_TIMEOUT_S)
        except pexpect.exceptions.TIMEOUT:
            console_cli.sendline('')
            console_cli.expect(LINECARD_CLI_PROMPT, timeout=PICOCOM_KILL_TIMEOUT_S)

        # Launch picocom to connect to linecard
        console_cli.sendline(f"sudo /usr/bin/picocom /dev/ttySCD{self.linecard_number}")
        console_cli.expect(PICOCOM_READY_PATTERN, timeout=PICOCOM_READY_TIMEOUT_S)
        console_cli.sendline('\n')

        # Authenticate to linecard
        try:
            match = console_cli.expect([LOGIN_USERNAME_PATTERN, LINECARD_CLI_PROMPT], timeout=LOGIN_USERNAME_TIMEOUT_S)
            if match == 0:
                console_cli.sendline(self.sonic_username)
                console_cli.expect(LOGIN_PWD_PATTERN, timeout=LOGIN_PWD_TIMEOUT_S)
                console_cli.sendline(self.sonic_password)
                if console_cli.expect([LINECARD_CLI_PROMPT, LOGIN_FAILURE_PATTERN],
                                      timeout=LOGIN_RESULT_TIMEOUT_S) == 1:
                    raise Exception(f"Failed to authenticate to linecard {self.linecard_number}")
        except pexpect.exceptions.TIMEOUT:
            raise Exception(f"Timeout waiting for login prompt on linecard {self.linecard_number}")
        except pexpect.exceptions.EOF:
            raise Exception(f"EOF reached while connecting to linecard {self.linecard_number}")

        self.console_cli = console_cli

    def send_command(
        self,
        cmd,
        expect_string=LINECARD_CLI_PROMPT,
        max_loops=None,
        read_timeout=None,
        cmd_verify=True,
    ):
        """
        Send a command using Netmiko-compatible arguments.

        Args:
            cmd: Command to send
            expect_string: String to expect after command completion (default: shell prompt)
            max_loops: Maximum timeout multiplier
            read_timeout: Maximum time to wait for the expected prompt
            cmd_verify: Accepted for compatibility; picocom does not verify command echo

        Returns:
            Command output (without the command echo)
        """
        self.console_cli.sendline(cmd)
        timeout = (
            read_timeout if read_timeout is not None else self.default_timeout
        )
        if max_loops:
            timeout = max(max_loops * self.delay_factor, timeout)
        self.console_cli.expect(expect_string, timeout=timeout)
        output = self.console_cli.before.decode()
        linesep = self.console_cli.linesep.decode()
        # Remove the command echo (first line)
        return output.split(linesep, 1)[1].strip() if linesep in output else output.strip()

    def send_command_timing(self, cmd, read_timeout=DEFAULT_TIMEOUT_S, last_read=DEFAULT_LAST_READ_S):
        """Send command and read output until no data arrives for last_read seconds."""
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
        self.logger.debug(
            "send_command_timing: finished in %.1fs, %d bytes collected",
            elapsed,
            len(output),
        )
        return output

    def write_channel(self, data, add_newline=True):
        if add_newline:
            self.console_cli.sendline(data)
        else:
            self.console_cli.send(data)

    def read_until_pattern(self, pattern, read_timeout=None):
        timeout = read_timeout if read_timeout is not None else self.default_timeout
        self.console_cli.expect(pattern, timeout=timeout)

    def _graceful_disconnect(self):
        """
        Run by disconnect(graceful=True): the disconnect() this class had before, unchanged.
        Disconnect from the linecard console and close the SSH connection.

        For Arista picocom: Ctrl+A, then Ctrl+X
        """
        assert self.console_cli.isalive(), "Console connection is not alive"

        self.logger.debug(f"Disconnecting from linecard {self.linecard_number}")

        # Exit picocom: Ctrl+A, then Ctrl+X
        self.console_cli.sendcontrol('a')
        self.console_cli.sendcontrol('x')

        # Wait for picocom exit confirmation or supervisor prompt
        try:
            self.console_cli.expect([LINECARD_CLI_PROMPT, PICOCOM_EXIT_PATTERN], timeout=PICOCOM_EXIT_TIMEOUT_S)
        except pexpect.exceptions.TIMEOUT:
            self.logger.warning("Timeout waiting for picocom exit confirmation")

        # Close the SSH connection
        self.console_cli.close(force=True)
        self.logger.debug("Linecard console connection closed.")
