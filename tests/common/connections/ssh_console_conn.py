import logging
import time
import re
import threading
from contextlib import contextmanager
from .base_console_conn import CONSOLE_SSH_DIGI_CONFIG, BaseConsoleConn, CONSOLE_SSH
try:
    from netmiko.ssh_exception import NetMikoAuthenticationException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException


logger = logging.getLogger(__name__)

# Serialize the temporary global Transport._preferred_kex mutation so concurrent
# non-console SSH sessions in the same process are not exposed to the legacy
# preference list while a console connection is being established.
_CONSOLE_KEX_OVERRIDE_LOCK = threading.Lock()

# Console SSH legacy KEX configuration. Populated by pytest_configure via
# configure_console_ssh_legacy_kex() based on --use-console-ssh-legacy-kex
# and --console-ssh-kex-algos. Default state is "disabled".
_LEGACY_KEX_DEFAULTS = (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
)
_legacy_kex_enabled = False
_legacy_kex_algos = ()


def configure_console_ssh_legacy_kex(enabled, algos=None):
    """
    Configure the legacy KEX override applied to console SSH connections.

    Intended to be called once from pytest_configure with values from the
    --use-console-ssh-legacy-kex and --console-ssh-kex-algos CLI options.

    Args:
        enabled: Bool. When False (default) no KEX override is applied.
        algos: Optional iterable or comma-separated string of KEX algorithm
            names. When None/empty, a built-in legacy default list is used.
    """
    global _legacy_kex_enabled, _legacy_kex_algos
    _legacy_kex_enabled = bool(enabled)

    parsed = ()
    if algos:
        if isinstance(algos, str):
            parsed = tuple(a.strip() for a in algos.split(",") if a.strip())
        else:
            parsed = tuple(s for s in (str(a).strip() for a in algos) if s)
    _legacy_kex_algos = parsed


def get_console_ssh_legacy_kex_status():
    """Return (enabled, effective_algos_tuple) snapshot for diagnostics/logging."""
    override = _get_console_kex_override()
    return _legacy_kex_enabled, tuple(override) if override else ()


def _get_console_kex_override():
    """
    Build an optional KEX preference override for Paramiko console SSH sessions.

    Disabled by default. Enabled via --use-console-ssh-legacy-kex (with
    optional --console-ssh-kex-algos="algo1,algo2,..."), wired in by
    pytest_configure -> configure_console_ssh_legacy_kex().
    """
    if not _legacy_kex_enabled:
        return None
    if _legacy_kex_algos:
        return _legacy_kex_algos
    return _LEGACY_KEX_DEFAULTS


@contextmanager
def _console_kex_override():
    """
    Temporarily prepend the configured legacy KEX algorithms to
    paramiko.Transport._preferred_kex for the duration of the with-block,
    then restore the original value.

    Paramiko does not expose a per-connection KEX preference hook on
    SSHClient, so we mutate the class attribute. The mutation is scoped to
    this context manager (covering only the netmiko/paramiko connect call
    for a single console session) and serialized via a module-level lock to
    prevent multiple console connection attempts from interleaving overrides.
    Note: other Paramiko sessions created in other threads during this
    window may still observe the overridden list.
    """
    kex_override = _get_console_kex_override()
    if not kex_override:
        yield
        return

    try:
        from paramiko.transport import Transport
    except Exception as e:
        logger.warning("Failed to import paramiko Transport for KEX override: %s", e)
        yield
        return

    _CONSOLE_KEX_OVERRIDE_LOCK.acquire()
    # Use __dict__ to distinguish a class-level override we previously set
    # from the default class attribute, so restoration is exact.
    had_attr = "_preferred_kex" in Transport.__dict__
    original = Transport.__dict__.get("_preferred_kex")
    try:
        current = tuple(getattr(Transport, "_preferred_kex", ()))
        # Preserve current order but move requested KEX algos to the front.
        merged = tuple(dict.fromkeys(kex_override + current))
        Transport._preferred_kex = merged
        logger.info("Console SSH legacy/custom KEX override enabled (scoped): %s", merged)
        yield
    finally:
        try:
            if had_attr:
                Transport._preferred_kex = original
            else:
                # Should not normally happen (Transport defines it), but be safe.
                try:
                    del Transport._preferred_kex
                except AttributeError:
                    pass
        finally:
            _CONSOLE_KEX_OVERRIDE_LOCK.release()


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

        # Optional, opt-in compatibility path for legacy console servers.
        # Scope the global Transport._preferred_kex mutation to only the
        # connection establishment of this console session.
        with _console_kex_override():
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
        # Attempt all sonic password
        for i in range(0, len(self.sonic_password)):
            password = self.sonic_password[i]
            try:
                self.login_stage_2(username=self.sonic_username,
                                   password=password)
            except NetMikoAuthenticationException as e:
                if i == len(self.sonic_password) - 1:
                    raise e
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

    def login_stage_2(self,
                      username,
                      password,
                      menu_port=None,
                      pri_prompt_terminator=r".*# ",
                      alt_prompt_terminator=r".*\$ ",
                      username_pattern=r"(?:user:|username|login|user name)",
                      pwd_pattern=r"assword",
                      delay_factor=1,
                      max_loops=20
                      ):
        """
        Perform a stage_2 login
        """
        delay_factor = self.select_delay_factor(delay_factor)
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
