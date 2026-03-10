import logging
import pexpect
import os

CONSERVER_CLI_PROMPT = "admin@[a-zA-Z0-9]{1,10}:~\\$"
CONSERVER_DEBUG_FILE = "/tmp/conserver_console_debug.log"


class ConserverConsoleConn():
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
        self.delay_factor = 1
        self.default_timeout = 30

        console_cli = pexpect.spawn(
            'console', ["-f", "-M", self.conserver_host,
                        self.conserver_name, "-p", self.port],
            timeout=self.default_timeout)

        if os.path.exists(CONSERVER_DEBUG_FILE):
            os.remove(CONSERVER_DEBUG_FILE)
        console_cli.logfile = open(CONSERVER_DEBUG_FILE, "wb")

        console_cli.sendline()
        match = console_cli.expect(["login", CONSERVER_CLI_PROMPT])
        if match == 0:
            console_cli.sendline(self.sonic_username)
            console_cli.expect("Password:")
            console_cli.sendline(self.sonic_password)
            console_cli.expect(CONSERVER_CLI_PROMPT)

        self.console_cli = console_cli

    def send_command(self, cmd, expect_string=CONSERVER_CLI_PROMPT, max_loops=None):
        self.console_cli.sendline(cmd)
        timeout = self.default_timeout
        if max_loops:
            timeout = max(max_loops * self.delay_factor, timeout)
        self.console_cli.expect(expect_string, timeout=timeout)
        output = self.console_cli.before.decode()
        return output.split(self.console_cli.linesep.decode(), 1)[1].strip()

    def write_channel(self, cmd):
        self.console_cli.sendline(cmd)

    def read_until_pattern(self, pattern):
        timeout = self.default_timeout
        self.console_cli.expect(pattern, timeout=timeout)

    def disconnect(self):
        assert self.console_cli.isalive()
        self.console_cli.sendline('\x05c.')
        self.console_cli.close(force=True)
        self.logger.debug("Conserver connection closed.")
