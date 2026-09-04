import logging
import pexpect
import os
import select
import time

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

    def _sendline_with_timeout(self, cmd, timeout):
        """Send one command line to conserver without an unbounded PTY write.

        pexpect.sendline() can block inside os.write() before read_timeout is
        applied. Use nonblocking partial writes so the DUT still receives one
        logical command line, while the local write path is bounded by timeout.
        """
        child_fd = getattr(self.console_cli, "child_fd", None)
        if child_fd is None:
            self.console_cli.sendline(cmd)
            return

        def to_bytes(data):
            """Convert console data to bytes using the pexpect encoding."""
            if isinstance(data, bytes):
                return data
            encoding = getattr(self.console_cli, "encoding", None) or "utf-8"
            return str(data).encode(encoding)

        data = to_bytes(cmd) + to_bytes(self.console_cli.linesep)
        write_start = time.monotonic()
        deadline = write_start + timeout
        sent = 0
        was_blocking = os.get_blocking(child_fd)

        os.set_blocking(child_fd, False)
        try:
            while sent < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.logger.info(
                        "Timed out writing console command after %s seconds "
                        "(%s/%s bytes sent)",
                        timeout, sent, len(data)
                    )
                    raise TimeoutError(
                        "Timed out writing console command after {} seconds "
                        "({}/{} bytes sent)".format(timeout, sent, len(data))
                    )

                _, writable, _ = select.select([], [child_fd], [], remaining)
                if not writable:
                    continue

                try:
                    sent += os.write(child_fd, data[sent:])
                except (BlockingIOError, InterruptedError):
                    continue
        finally:
            os.set_blocking(child_fd, was_blocking)

        self.logger.info(
            "Console command write completed in %.1fs, %d bytes sent",
            time.monotonic() - write_start, sent
        )

    def send_command_timing(self, cmd, read_timeout=30, last_read=1.0):
        """Send command and read output until no data for 'last_read' seconds."""
        self.logger.debug("send_command_timing: cmd='%s'", cmd[:80])

        start_time = time.monotonic()
        self._sendline_with_timeout(cmd, read_timeout)

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
