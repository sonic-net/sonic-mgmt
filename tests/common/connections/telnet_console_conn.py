import time
import re
from .base_console_conn import BaseConsoleConn, DutLoginFailed


class TelnetConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        # Attach to the console line only: no DUT login and no write to the line.
        self.attach_only = kwargs.pop("attach_only", False)
        # A telnet console has no console server login: the connection reaches the DUT
        # serial line directly, and telnet_login() tries the DUT passwords on it.
        self.sonic_password = kwargs['sonic_password']
        kwargs['host'] = kwargs['console_host']
        kwargs['port'] = kwargs['console_port']
        kwargs['username'] = kwargs['sonic_username']
        kwargs['console_username'] = kwargs['sonic_username']
        kwargs['console_password'] = [None]
        kwargs['device_type'] = "_telnet"
        super(TelnetConsoleConn, self).__init__(**kwargs)

    def _try_session_preparation(self, force_data=True):
        # netmiko writes a RETURN before session preparation; an attach-only console must not.
        return super(TelnetConsoleConn, self)._try_session_preparation(force_data=force_data and not self.attach_only)

    def session_preparation(self):
        if not self.attach_only:
            super(TelnetConsoleConn, self).session_preparation()

    def cleanup(self):
        # netmiko's cleanup writes "exit" to the line; an attach-only console only closes.
        if not self.attach_only:
            super(TelnetConsoleConn, self).cleanup()

    def telnet_login(
        self,
        pri_prompt_terminator=r".*# ",
        alt_prompt_terminator=r".*\$ ",
        username_pattern=r"(?:user:|username|login|user name)",
        pwd_pattern=r"assword",
        delay_factor=1,
        max_loops=20,
    ):
        """Telnet login. Can be username/password or just password."""
        if self.attach_only:
            return ""
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        login_failure_prompt = r".*incorrect"
        username_sent = False
        password_sent = False
        password_index = 0
        i = 1
        while i <= max_loops:
            try:
                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if not username_sent and re.search(username_pattern, output, flags=re.I):
                    self.write_channel(self.username + self.TELNET_RETURN)
                    username_sent = True
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg = output

                # Search for password pattern / send password
                if username_sent and not password_sent and re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.sonic_password[password_index] + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    password_sent = True
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Support direct telnet through terminal server
                if re.search(r"initial configuration dialog\? \[yes/no\]: ", output):
                    self.write_channel("no" + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    count = 0
                    while count < 15:
                        output = self.read_channel()
                        return_msg += output
                        if re.search(r"ress RETURN to get started", output):
                            output = ""
                            break
                        time.sleep(2 * delay_factor)
                        count += 1

                # Check for device with no password configured
                if re.search(r"assword required, but none set", output):
                    self.remote_conn.close()
                    msg = "Login failed - Password required, but none set: {}".format(
                        self.host
                    )
                    raise DutLoginFailed(msg)

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                    alt_prompt_terminator, return_msg, flags=re.M
                ):
                    return return_msg

                #  Check if login failed
                if re.search(login_failure_prompt, output, flags=re.M):
                    if password_index < len(self.sonic_password) - 1:
                        # Try the next password at the DUT's next login prompt, on this connection
                        password_index += 1
                        username_sent = password_sent = False
                        i = 1
                        time.sleep(1 * delay_factor)
                        continue
                    self.remote_conn.close()
                    # Wait a short time or the next login will be refused
                    time.sleep(1 * delay_factor)
                    msg = "Login failed: {}".format(self.host)
                    raise DutLoginFailed(msg)

                self.write_channel(self.TELNET_RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise DutLoginFailed(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise DutLoginFailed(msg)
