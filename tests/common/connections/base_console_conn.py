"""
Base class for console connection of SONiC devices
"""

import logging
import time
import paramiko

from netmiko.cisco_base_connection import CiscoBaseConnection

try:
    from netmiko.ssh_exception import NetMikoAuthenticationException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException

# For interactive shell
import sys
import socket
import termios
import tty
import select

logger = logging.getLogger(__name__)

# All supported console types
# Console login via telnet (mad console)
CONSOLE_TELNET = "console_telnet"
# Console login via SSH (digi)
CONSOLE_SSH = "console_ssh"
# Console login via SSH, then login to devices by 'menu ports'
CONSOLE_SSH_MENU_PORTS = "console_ssh_menu_ports"
# Console login via SSH based on port
CONSOLE_SSH_TO_PORT = "console_ssh_to_port"
# Console login via SSH, no stage 2 login (Digi Config Menu)
CONSOLE_SSH_DIGI_CONFIG = "console_ssh_digi_config"
# Console login via SSH, no stage 2 login (SONiC switch config)
CONSOLE_SSH_SONIC_CONFIG = "console_ssh_sonic_config"
# Console login via SSH, no stage 2 login (Cisco switch config)
CONSOLE_SSH_CISCO_CONFIG = "console_ssh_cisco_config"
# Console login via conserver
CONSOLE_CONSERVER = "console_conserver"
# Console login via SSH to Raritan
CONSOLE_SSH_RARITAN_CONFIG = "console_ssh_to_port_raritan_config"

DEFAULT_FAST_CLI = False
# Prompt terminators set_base_prompt() accepts.
PRI_PROMPT_TERMINATOR = '#'
ALT_PROMPT_TERMINATOR = '$'


class DutLoginFailed(NetMikoAuthenticationException):
    """The console login succeeded, but the login on the DUT behind it failed."""
    pass


class ConsoleConnectTimeout(Exception):
    """The console connection was not made before the connect deadline."""
    pass


class BaseConsoleConn(CiscoBaseConnection):
    # time.monotonic() deadline for the whole connect; None means no limit.
    _connect_deadline = None

    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        # Popped so it never reaches netmiko; cleared once the connection is made.
        self._connect_deadline = kwargs.pop("connect_deadline", None)
        # Clear additional args before passing to BaseConsoleConn
        all_passwords = kwargs['console_password']
        key_to_rm = [
            "console_username",
            "console_password",
            "console_host",
            "console_port",
            "sonic_username",
            "sonic_password",
            "console_type",
            "console_device",
            "direct_ssh_port",
        ]
        for key in key_to_rm:
            if key in kwargs:
                del kwargs[key]

        # netmiko's fast_cli=True default silently sets global_delay_factor
        # to 0.1, which shrinks login polling budgets too tightly for
        # serial-console getty timing. Default it off; callers can still
        # opt in via kwargs.
        kwargs.setdefault('fast_cli', DEFAULT_FAST_CLI)

        # Allow legacy KEX and host key algorithms for older console servers
        # (e.g. Cisco SSH-2.0-Cisco-1.25) that only support legacy crypto.
        # paramiko 5.x removed these from _preferred_kex, _kex_info,
        # _preferred_keys, _key_info, and RSAKey.HASHES.
        try:
            from paramiko.kex_group14 import KexGroup14SHA256
            from paramiko.kex_gex import KexGexSHA256
            from paramiko.rsakey import RSAKey
            from hashlib import sha1 as _sha1
            from cryptography.hazmat.primitives.hashes import SHA1

            # Reconstruct legacy KEX classes from existing SHA256 variants
            class _KexGroup14SHA1(KexGroup14SHA256):
                name = "diffie-hellman-group14-sha1"
                hash_algo = _sha1

            class _KexGexSHA1(KexGexSHA256):
                name = "diffie-hellman-group-exchange-sha1"
                hash_algo = _sha1

            _legacy_kex = {
                "diffie-hellman-group14-sha1": _KexGroup14SHA1,
                "diffie-hellman-group-exchange-sha1": _KexGexSHA1,
            }
            for kex_name, kex_cls in _legacy_kex.items():
                if kex_name not in paramiko.Transport._preferred_kex:
                    paramiko.Transport._preferred_kex += (kex_name,)
                if kex_name not in paramiko.Transport._kex_info:
                    paramiko.Transport._kex_info[kex_name] = kex_cls

            # Re-enable ssh-rsa host key support
            if "ssh-rsa" not in paramiko.Transport._preferred_keys:
                paramiko.Transport._preferred_keys += ("ssh-rsa",)
            if "ssh-rsa" not in paramiko.Transport._key_info:
                paramiko.Transport._key_info["ssh-rsa"] = RSAKey
            if "ssh-rsa" not in RSAKey.HASHES:
                RSAKey.HASHES["ssh-rsa"] = SHA1
        except Exception as e:
            logger.debug("Could not re-enable legacy SSH algorithms for console: %s", e)

        for i in range(0, len(all_passwords)):
            kwargs['password'] = all_passwords[i]
            time_left = self._connect_time_left()
            if time_left is not None:
                # netmiko's TCP connect, SSH banner and login waits get only the time left.
                kwargs.update(conn_timeout=time_left, banner_timeout=time_left, auth_timeout=time_left)
            try:
                super(BaseConsoleConn, self).__init__(**kwargs)
            except DutLoginFailed:
                # One way: the console login succeeded, so the next console password would not help.
                raise
            except NetMikoAuthenticationException as e:
                if i == len(all_passwords) - 1:
                    raise e
            else:
                break
        self._connect_deadline = None

    def _connect_time_left(self):
        """Seconds left before the connect deadline, None without one; raises once it has passed."""
        if self._connect_deadline is None:
            return None
        time_left = self._connect_deadline - time.monotonic()
        if time_left <= 0:
            raise ConsoleConnectTimeout()
        return time_left

    def read_channel(self):
        # Every wait during the connect reads the channel, so this check bounds the whole connect.
        self._connect_time_left()
        return super(BaseConsoleConn, self).read_channel()

    def select_delay_factor(self, delay_factor):
        # None means the connection's delay factor, the constructor's global_delay_factor.
        if delay_factor is None:
            return self.global_delay_factor
        return super(BaseConsoleConn, self).select_delay_factor(delay_factor)

    def set_base_prompt(self, pri_prompt_terminator=PRI_PROMPT_TERMINATOR,
                        alt_prompt_terminator=ALT_PROMPT_TERMINATOR, delay_factor=None):
        return super(BaseConsoleConn, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            delay_factor=delay_factor)

    def write_and_poll(self, command, pattern):
        """
        Write a command to terminal and poll until expected pattern is found or timeout
        """
        self.write_channel(command + self.RETURN)
        self.read_until_pattern(pattern=pattern)

    def disable_paging(self, command="", delay_factor=None):
        # not supported
        pass

    def find_prompt(self, delay_factor=None, **kwargs):
        return super(BaseConsoleConn, self).find_prompt(delay_factor, **kwargs)

    def clear_buffer(self):
        # todo
        super(BaseConsoleConn, self).clear_buffer()

    def enable(self):
        # not support config mode for now
        pass

    def config_mode(self):
        # not support config mode for now
        pass

    def exit_config_mode(self, exit_config, pattern):
        # not support config mode for now
        pass

    def cleanup(self):
        super(BaseConsoleConn, self).cleanup()

    def disconnect(self):
        super(BaseConsoleConn, self).disconnect()

    def posix_shell(self):
        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            self.remote_conn.settimeout(0.0)

            while True:
                r, w, e = select.select([self.remote_conn, sys.stdin], [], [])
                if self.remote_conn in r:
                    try:
                        x = self.remote_conn.recv(1024)
                        if len(x) == 0:
                            sys.stdout.write("\r\n*** EOF\r\n")
                            break

                        x = x.decode('ISO-8859-9')
                        sys.stdout.write(x)
                        sys.stdout.flush()
                    except socket.timeout:
                        pass
                if sys.stdin in r:
                    x = sys.stdin.read(1)
                    if len(x) == 0:
                        break
                    self.remote_conn.send(x)

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
