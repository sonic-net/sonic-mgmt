import time
import re
from .base_console_conn import BaseConsoleConn, DutLoginFailed

LOGIN_FAILURE_PATTERN = r".*incorrect"
NO_PASSWORD_SET_PATTERN = r"assword required, but none set"
INITIAL_CONFIG_DIALOG_PATTERN = r"initial configuration dialog\? \[yes/no\]: "
PRESS_RETURN_PATTERN = r"ress RETURN to get started"
# Prompts telnet_login() looks for: logged in (# or $), username and password.
LOGIN_PRI_PROMPT_TERMINATOR = r".*# "
LOGIN_ALT_PROMPT_TERMINATOR = r".*\$ "
LOGIN_USERNAME_PATTERN = r"(?:user:|username|login|user name)"
LOGIN_PWD_PATTERN = r"assword"
# How telnet_login() uses the waits and limits below. The telnet connection reaches the
# DUT serial line directly, and netmiko's constructor runs telnet_login() on it. Each wait
# is multiplied by the delay_factor argument (DEFAULT_DELAY_FACTOR by default).
#   a. attach_only returns at once. Otherwise pause RESPONSE_WAIT_S, then run up to
#      max_loops rounds (DEFAULT_LOGIN_MAX_LOOPS by default). Each round reads the line,
#      handles what it finds as in b to d, then sends a CR and pauses READ_INTERVAL_S.
#   b. At a username prompt, send the username and pause RESPONSE_WAIT_S. At a password
#      prompt, send the password and pause READ_INTERVAL_S.
#   c. At a Cisco initial configuration dialog, answer "no" and pause READ_INTERVAL_S,
#      then read up to DIALOG_MAX_READS times, DIALOG_READ_INTERVAL_S apart, until
#      "Press RETURN to get started".
#   d. After a rejected password, pause RESPONSE_WAIT_S and try the next password at the
#      next login prompt, starting the rounds again. After the last password, close the
#      line, pause RESPONSE_WAIT_S so the next login is not refused, and fail.
#   e. After the last round, send a CR, pause READ_INTERVAL_S and check once more for a
#      prompt before failing.
READ_INTERVAL_S = 0.5
RESPONSE_WAIT_S = 1
DIALOG_READ_INTERVAL_S = 2
DIALOG_MAX_READS = 15
# Sets the minimum delay factor. It can be overridden to be larger, but not smaller.
DEFAULT_DELAY_FACTOR = 1
DEFAULT_LOGIN_MAX_LOOPS = 20


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
        kwargs.setdefault('global_delay_factor', DEFAULT_DELAY_FACTOR)
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
        pri_prompt_terminator=LOGIN_PRI_PROMPT_TERMINATOR,
        alt_prompt_terminator=LOGIN_ALT_PROMPT_TERMINATOR,
        username_pattern=LOGIN_USERNAME_PATTERN,
        pwd_pattern=LOGIN_PWD_PATTERN,
        delay_factor=DEFAULT_DELAY_FACTOR,
        max_loops=DEFAULT_LOGIN_MAX_LOOPS,
    ):
        """Telnet login. Can be username/password or just password."""
        if self.attach_only:
            return ""
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(RESPONSE_WAIT_S * delay_factor)

        output = ""
        return_msg = ""
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
                    time.sleep(RESPONSE_WAIT_S * delay_factor)
                    output = self.read_channel()
                    return_msg = output

                # Search for password pattern / send password
                if username_sent and not password_sent and re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.sonic_password[password_index] + self.TELNET_RETURN)
                    time.sleep(READ_INTERVAL_S * delay_factor)
                    password_sent = True
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Support direct telnet through terminal server
                if re.search(INITIAL_CONFIG_DIALOG_PATTERN, output):
                    self.write_channel("no" + self.TELNET_RETURN)
                    time.sleep(READ_INTERVAL_S * delay_factor)
                    count = 0
                    while count < DIALOG_MAX_READS:
                        output = self.read_channel()
                        return_msg += output
                        if re.search(PRESS_RETURN_PATTERN, output):
                            output = ""
                            break
                        time.sleep(DIALOG_READ_INTERVAL_S * delay_factor)
                        count += 1

                # Check for device with no password configured
                if re.search(NO_PASSWORD_SET_PATTERN, output):
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
                if re.search(LOGIN_FAILURE_PATTERN, output, flags=re.M):
                    if password_index < len(self.sonic_password) - 1:
                        # Try the next password at the DUT's next login prompt, on this connection
                        password_index += 1
                        username_sent = password_sent = False
                        i = 1
                        time.sleep(RESPONSE_WAIT_S * delay_factor)
                        continue
                    self.remote_conn.close()
                    # Wait a short time or the next login will be refused
                    time.sleep(RESPONSE_WAIT_S * delay_factor)
                    msg = "Login failed: {}".format(self.host)
                    raise DutLoginFailed(msg)

                self.write_channel(self.TELNET_RETURN)
                time.sleep(READ_INTERVAL_S * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise DutLoginFailed(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(READ_INTERVAL_S * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise DutLoginFailed(msg)
