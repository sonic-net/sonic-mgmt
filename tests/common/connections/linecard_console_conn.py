import logging
import pexpect
import os

LINECARD_CLI_PROMPT = r"admin@[a-zA-Z0-9\-]{1,20}:~\$"
LINECARD_DEBUG_FILE = "/tmp/linecard_console_debug.log"


class UnsupportedPlatformError(Exception):
    """Exception raised when the platform/hwsku is not supported for linecard console access."""
    pass


class LinecardConsoleConn():
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
        self.delay_factor = 1
        self.default_timeout = 30

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
        supervisor_ip = kwargs['supervisor_ip']
        sonic_username = kwargs['sonic_username']
        sonic_password = (kwargs['sonic_password'][0] if isinstance(kwargs['sonic_password'], list)
                          else kwargs['sonic_password'])
        slot_num = kwargs['slot_num']

        # Platform-specific slot conversion (Arista: slot3 -> SCD0, slot7 -> SCD4)
        self.linecard_number = str(int(slot_num[len("slot"):]) - 3)

        # SSH to supervisor
        ssh_cmd = f'ssh {sonic_username}@{supervisor_ip} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
        self.logger.debug(f"Connecting to supervisor at {supervisor_ip}")

        console_cli = pexpect.spawn(ssh_cmd, timeout=self.default_timeout, echo=False)

        # Set up debug logging
        if os.path.exists(LINECARD_DEBUG_FILE):
            os.remove(LINECARD_DEBUG_FILE)
        console_cli.logfile = open(LINECARD_DEBUG_FILE, "wb")

        # Authenticate to supervisor
        console_cli.expect('[Pp]assword:')
        console_cli.sendline(sonic_password)
        console_cli.expect(LINECARD_CLI_PROMPT)

        # Kill any existing picocom sessions
        console_cli.sendline('sudo pkill -9 picocom || true')
        try:
            console_cli.expect(LINECARD_CLI_PROMPT, timeout=5)
        except pexpect.exceptions.TIMEOUT:
            console_cli.sendline('')
            console_cli.expect(LINECARD_CLI_PROMPT, timeout=5)

        # Launch picocom to connect to linecard
        console_cli.sendline(f"sudo /usr/bin/picocom /dev/ttySCD{self.linecard_number}")
        console_cli.expect('Terminal ready', timeout=20)
        console_cli.sendline('\n')

        # Authenticate to linecard
        try:
            match = console_cli.expect(['login:', LINECARD_CLI_PROMPT], timeout=20)
            if match == 0:
                console_cli.sendline(sonic_username)
                console_cli.expect('[Pp]assword:', timeout=10)
                console_cli.sendline(sonic_password)
                if console_cli.expect([LINECARD_CLI_PROMPT, 'Login incorrect'], timeout=30) == 1:
                    raise Exception(f"Failed to authenticate to linecard {self.linecard_number}")
        except pexpect.exceptions.TIMEOUT:
            raise Exception(f"Timeout waiting for login prompt on linecard {self.linecard_number}")
        except pexpect.exceptions.EOF:
            raise Exception(f"EOF reached while connecting to linecard {self.linecard_number}")

        self.console_cli = console_cli

    def send_command(self, cmd, expect_string=LINECARD_CLI_PROMPT, max_loops=None):
        """
        Send a command to the linecard console and wait for response.

        Args:
            cmd: Command to send
            expect_string: String to expect after command completion (default: shell prompt)
            max_loops: Maximum timeout multiplier

        Returns:
            Command output (without the command echo)
        """
        self.console_cli.sendline(cmd)
        timeout = self.default_timeout
        if max_loops:
            timeout = max(max_loops * self.delay_factor, timeout)
        self.console_cli.expect(expect_string, timeout=timeout)
        output = self.console_cli.before.decode()
        linesep = self.console_cli.linesep.decode()
        # Remove the command echo (first line)
        return output.split(linesep, 1)[1].strip() if linesep in output else output.strip()

    def disconnect(self):
        """
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
            self.console_cli.expect([LINECARD_CLI_PROMPT, 'Thanks for using picocom'], timeout=20)
        except pexpect.exceptions.TIMEOUT:
            self.logger.warning("Timeout waiting for picocom exit confirmation")

        # Close the SSH connection
        self.console_cli.close(force=True)
        self.logger.debug("Linecard console connection closed.")
