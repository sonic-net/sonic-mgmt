import time
import re
from .base_console_conn import CONSOLE_SSH_DIGI_CONFIG, BaseConsoleConn, CONSOLE_SSH
try:
    from netmiko.ssh_exception import NetMikoAuthenticationException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException


class SSHConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        if "console_username" not in kwargs \
                or "console_password" not in kwargs:
            raise ValueError("Either console_username or console_password is not set")

        # Console via SSH connection need two groups of user/passwd
        self.sonic_username = kwargs['sonic_username']
        self.sonic_password = kwargs['sonic_password']

        # Store console type for later use
        self.console_type = kwargs['console_type']

        if self.console_type == CONSOLE_SSH:
            # Login requires port to be provided
            kwargs['username'] = kwargs['console_username'] + r':' + str(kwargs['console_port'])
            self.menu_port = None
        elif self.console_type.endswith("config"):
            # Login to config menu only requires username
            kwargs['username'] = kwargs['console_username']
        else:
            # Login requires menu port
            kwargs['username'] = kwargs['console_username']
            self.menu_port = kwargs['console_port']
        kwargs['password'] = kwargs['console_password']
        kwargs['host'] = kwargs['console_host']
        kwargs['device_type'] = "_ssh"
        super(SSHConsoleConn, self).__init__(**kwargs)

    def session_preparation(self):
        session_init_msg = self._test_channel_read()
        self.logger.debug(session_init_msg)

        if re.search(
            r"(Port is in use. Closing connection...|Cannot connect: line \[\d{2}\] is busy)",
            session_init_msg,
            flags=re.M
        ):
            console_port = self.username.split(':')[-1]
            raise PortInUseException(f"Host closed connection, as console port '{console_port}' is currently occupied.")

        if self.console_type.endswith("config"):
            # We can skip stage 2 login for config menu connections
            self.session_preparation_finalise()
            return

        if (self.menu_port):
            # For devices logining via menu port, 2 additional login are needed
            # Since we have attempted all passwords in __init__ of base class until successful login
            # So self.username and self.password must be the correct ones
            self.login_stage_2(username=self.username,
                               password=self.password,
                               menu_port=self.menu_port,
                               pri_prompt_terminator=r".*login")
        # A previous console test that did not log out cleanly leaves a
        # logged-in shell on the DUT serial line, so a new connection lands
        # on a shell prompt instead of "login:". Sending the username then
        # just runs it as a shell command ("admin: command not found") and the
        # login never starts, which cascades to every later console test.
        # Recover to a clean login prompt before attempting to log in.
        self._recover_to_login_prompt()
        # Attempt all sonic password. A wrong password must not prevent a
        # subsequent correct password in the list from succeeding, so we
        # re-synchronise the terminal back to a fresh "login:" prompt between
        # attempts (the failed attempt leaves a "Login incorrect" banner in the
        # buffer that would otherwise desync the next login).
        for i in range(0, len(self.sonic_password)):
            password = self.sonic_password[i]
            try:
                self.login_stage_2(username=self.sonic_username,
                                   password=password)
            except NetMikoAuthenticationException as e:
                if i == len(self.sonic_password) - 1:
                    raise e
                # Drain any leftover "Login incorrect" output and wait until the
                # getty presents a clean login prompt before trying the next
                # password in the list.
                self._resync_to_login_prompt()
            else:
                break

        self.session_preparation_finalise()

    def session_preparation_finalise(self):
        """
        Helper function to handle final stages of session preparation.
        """
        # Digi config menu has a unique prompt terminator (----->)
        if self.console_type == CONSOLE_SSH_DIGI_CONFIG:
            self.set_base_prompt(">")
        else:
            self.set_base_prompt()

        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def _recover_to_login_prompt(self, max_attempts=4, delay_factor=1):
        """
        Ensure the console is at a fresh "login:" prompt before logging in.

        If a previous console session was left logged in (its cleanup did not
        run or could not log out), the serial line still has an authenticated
        shell and a new connection lands on the shell prompt instead of
        "login:". In that case the username sent below is interpreted as a
        shell command and the login never happens. Detect a leftover shell
        prompt and send "exit" to return to a clean login prompt so each
        console test is independent of the previous one's teardown.
        """
        shell_prompt_patterns = (
            r'admin@.*:.*[\$#]',
            r'root@.*:.*#',
            r'.*@sonic.*[\$#]',
        )
        # Floor the delay factor: with a small global delay factor the probe
        # would read back before the serial console echoes the prompt (which
        # can lag a second or two), miss a leftover shell prompt, and leave
        # the stale session in place.
        delay_factor = max(self.select_delay_factor(delay_factor), 1)
        for _ in range(max_attempts):
            try:
                self.write_channel(self.RETURN)
                # Accumulate output over a couple of seconds so a lagging
                # shell/login prompt is reliably observed.
                output = ""
                for _ in range(4):
                    time.sleep(0.5 * delay_factor)
                    output += self.read_channel()
            except Exception as e:
                self.logger.warning(f"Error probing console state: {e}")
                return
            # Already at a login prompt -> nothing to recover.
            if re.search(r"login:\s*$", output, flags=re.I | re.M):
                return
            # Logged-in shell left over from a previous session -> log out.
            if any(re.search(p, output) for p in shell_prompt_patterns):
                self.logger.warning(
                    "Console is at a leftover shell prompt; sending 'exit' to "
                    "return to the login prompt")
                try:
                    self.write_channel("exit" + self.RETURN)
                    time.sleep(1 * delay_factor)
                except Exception as e:
                    self.logger.warning(f"Error sending exit during recovery: {e}")
                    return
                continue
            # Unknown / transient state: try once more.
        # Best effort: clear whatever is pending so the login starts clean.
        self.clear_buffer()

    def _resync_to_login_prompt(self, max_loops=20, delay_factor=1):
        """
        Re-synchronise the console to a fresh "login:" prompt.

        After a failed password attempt the getty prints a "Login incorrect"
        banner followed by a new login prompt. Drain that stale output and wait
        for a clean login prompt so the next credential in the list starts from
        a known state (otherwise the leftover banner desyncs the next attempt).
        """
        # Floor the delay factor so the wait spans the pam_faildelay window
        # (~3s) that follows a failed login before the fresh prompt appears.
        delay_factor = max(self.select_delay_factor(delay_factor), 1)
        # Drop any pending "Login incorrect" / banner output.
        self.clear_buffer()
        i = 1
        while i <= max_loops:
            try:
                self.write_channel(self.RETURN)
                time.sleep(0.5 * delay_factor)
                output = self.read_channel()
                # A fresh prompt ends with "login:" (with the colon); this does
                # not match the "Login incorrect" failure banner.
                if re.search(r"login:\s*$", output, flags=re.I | re.M):
                    self.clear_buffer()
                    return
            except EOFError:
                self.remote_conn.close()
                raise NetMikoAuthenticationException(
                    "Login failed: {}".format(self.host))
            i += 1
        # Best effort: leave the buffer clean for the next attempt.
        self.clear_buffer()

    def login_stage_2(self,
                      username,
                      password,
                      menu_port=None,
                      pri_prompt_terminator=r".*# ",
                      alt_prompt_terminator=r".*\$ ",
                      username_pattern=r"(?:user:|username|login:|user name)",
                      pwd_pattern=r"assword",
                      delay_factor=1,
                      max_loops=20
                      ):
        """
        Perform a stage_2 login
        """
        delay_factor = self.select_delay_factor(delay_factor)
        # The serial console can take a few seconds to emit the password
        # prompt, and up to ~3s longer after a wrong password because of
        # pam_faildelay. A small global delay factor makes the wait loop give
        # up in ~1s, before the prompt appears, so the login fails with
        # "Socket is closed". Floor the delay factor so the loop waits long
        # enough (max_loops * 0.5 * delay_factor) to see the prompt.
        delay_factor = max(delay_factor, 1)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        i = 1
        menu_port_sent = False
        user_sent = False
        password_sent = False
        # The following prompt is only for SONiC
        # Need to add more login failure prompt for other system
        login_failure_prompt = r".*incorrect"
        while i <= max_loops:
            try:
                if menu_port and not menu_port_sent:
                    self.write_and_poll("menu ports", "Selection:")
                    self.write_channel(str(self.menu_port) + self.RETURN)
                    menu_port_sent = True

                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if not user_sent and re.search(username_pattern, output, flags=re.I):
                    self.write_channel(username + self.RETURN)
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    user_sent = True

                # Search for password pattern / send password
                # Use return_msg (accumulated) instead of output to handle cases where
                # 'Password:' prompt is split across multiple TCP reads (e.g. 'Pa' + 'ssword:')
                if user_sent and not password_sent and re.search(pwd_pattern, return_msg, flags=re.I):
                    self.write_channel(password + self.RETURN)
                    time.sleep(0.5 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    password_sent = True
                    if re.search(
                            pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                        alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                # Check if login failed
                if re.search(login_failure_prompt, output, flags=re.M):
                    # Wait a short time or the next login will be refused
                    time.sleep(1 * delay_factor)
                    msg = "Login failed: {}".format(self.host)
                    raise NetMikoAuthenticationException(msg)

                # Only send blank CR to wake up terminal when still waiting for username prompt;
                # once username has been sent, stop sending CRs so no empty password arrives before 'Password:' prompt
                if not user_sent:
                    self.write_channel(self.RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise NetMikoAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise NetMikoAuthenticationException(msg)

    def _is_at_sonic_prompt(self):
        """
        Check if we're at a SONiC shell prompt by examining the last line in the buffer.

        Returns:
            bool: True if at SONiC prompt, False otherwise (including GRUB, ONIE, boot stages, etc.)
        """
        try:
            # Read whatever is currently in the buffer
            output = self.read_channel()
        except Exception as e:
            self.logger.warning(f"Error reading channel: {e}, assuming not at SONiC prompt")
            return False

        if not output:
            self.logger.warning("Console buffer is empty, cannot determine prompt state")
            return False

        # Get the last line (most recent output, likely the current prompt)
        # Split by common line endings and get the last non-empty line
        lines = output.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        last_line = ''
        for line in reversed(lines):
            if line.strip():
                last_line = line
                break
        else:
            self.logger.debug("No non-empty lines in buffer")
            return False

        # Check for SONiC prompt patterns (admin@sonic:~$, root@sonic:~#, etc.)
        sonic_prompt_patterns = [
            r'admin@.*:.*[\$#]',
            r'root@.*:.*#',
            r'.*@sonic.*[\$#]'
        ]

        # Check if the last line matches a SONiC prompt
        for pattern in sonic_prompt_patterns:
            if re.search(pattern, last_line):
                self.logger.debug(f"Matched SONiC prompt pattern: {pattern}")
                return True

        self.logger.debug(f"Last line does not match SONiC prompt: {last_line}")
        return False

    def cleanup(self):
        """
        Cleanup console connection.
        Only send 'exit' if we're certain the DUT is at a SONiC prompt.
        This prevents issues during reboot when DUT might be in GRUB or other boot stages.
        """
        # If we are in SONiC and session is ready, send an exit to logout
        if self._is_at_sonic_prompt():
            self.logger.warning("At SONiC prompt, sending exit to logout")
            try:
                self.send_command(command_string="exit", expect_string="login:")
            except Exception as e:
                self.logger.warning(f"Failed to send exit command during cleanup: {e}")

        # remote_conn must be closed, or the SSH session will be kept on Digi,
        # and any other login is prevented
        self.remote_conn.close()
        del self.remote_conn


class PortInUseException(SSHException):
    '''Exception to denote a console port is in use.'''
    pass
