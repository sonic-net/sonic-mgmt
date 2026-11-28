"""
Base class for console connection of SONiC devices
"""

import logging
import threading
import paramiko

from netmiko.cisco_base_connection import CiscoBaseConnection

try:
    from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

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


class ConsoleConnectTimeout(NetMikoTimeoutException, TimeoutError):
    """connect() did not finish within timeout_s; the connection was closed without writing."""
    pass


class BaseConsoleConn(CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        # Guards _connected and _sockets: disconnect() may come from another thread at any
        # point, even while connecting.
        self._state_lock = threading.Lock()
        self._connected = False
        timeout_s = kwargs.pop("timeout_s", None)
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

        self._connect_kwargs = kwargs
        self._console_passwords = all_passwords
        self.connect(timeout_s)

    def connect(self, timeout_s=None):
        """
        Connect, or connect again after disconnect(): try each console password in turn.
        Connecting while connected raises RuntimeError, and a failed connect is as if it never
        happened: nothing stays open and the object is not connected. With timeout_s, a connect
        still running after timeout_s seconds is closed without writing to the line
        (disconnect(graceful=False)) and raises ConsoleConnectTimeout.
        """
        with self._state_lock:
            if self._connected:
                raise RuntimeError("Already connected; call disconnect() first")
            self._connected = True
            self._sockets = []
        timed_out = threading.Event()
        timer = None
        if timeout_s is not None:
            def time_out():
                timed_out.set()
                self.disconnect(graceful=False)
            timer = threading.Timer(timeout_s, time_out)
            timer.start()
        try:
            self._try_console_passwords()
        except Exception as e:
            self._stop_timer(timer)
            # A failed constructor never returns the object for anyone to disconnect.
            self.disconnect(graceful=False)
            if timed_out.is_set():
                raise ConsoleConnectTimeout() from e
            raise
        self._stop_timer(timer)
        if timed_out.is_set():
            # The timer fired just as the connect finished: a timeout all the same.
            raise ConsoleConnectTimeout()

    def _stop_timer(self, timer):
        """Stop the connect() timer, waiting for it if it is firing."""
        if timer is not None:
            timer.cancel()
            timer.join()

    def _try_console_passwords(self):
        kwargs = dict(self._connect_kwargs)
        for i in range(0, len(self._console_passwords)):
            kwargs['password'] = self._console_passwords[i]
            try:
                # netmiko connects in its __init__; running it again connects again.
                super(BaseConsoleConn, self).__init__(**kwargs)
            except DutLoginFailed:
                # One way: the console login succeeded, so the next console password would not help.
                raise
            except NetMikoAuthenticationException as e:
                if i == len(self._console_passwords) - 1:
                    raise e
            else:
                break

    def _open_socket(self, host, port, timeout, next_address_errnos=None):
        """
        Helper used in two places, SSHConsoleConn._build_ssh_client() and
        TelnetConsoleConn.establish_connection(), the overrides of netmiko's _build_ssh_client()
        and establish_connection(). It performs the same function as the TCP connect in paramiko's
        SSHClient.connect() (SSH) and socket.create_connection() (telnet), with the addition of
        registering the socket, so that disconnect(graceful=False) can shut it down at any time,
        even mid-connect; once disconnected, it raises NetMikoTimeoutException instead of connecting.

        Known differences, not fixed:
        - SSH, every address refused or unreachable: raises the last error, not paramiko's
          NoValidConnectionsError; netmiko turns both into the same NetmikoTimeoutException.
        - SSH, conn_timeout=None: waits without limit instead of Python's global socket timeout;
          conn_timeout is netmiko's default 10 s here, and no global socket timeout is set.
        - telnet: Python's audit event telnetlib.Telnet.open is not raised; we use no audit hooks.
        """
        error = None
        for family, sock_type, proto, _, address in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            sock = socket.socket(family, sock_type, proto)
            with self._state_lock:
                if not self._connected:
                    sock.close()
                    raise NetMikoTimeoutException("Disconnected; nothing is opened until the next connect()")
                self._sockets.append(sock)
            try:
                sock.settimeout(timeout)
                sock.connect(address)
                return sock
            except OSError as e:
                sock.close()
                if next_address_errnos is not None and e.errno not in next_address_errnos:
                    raise
                error = e
        raise error

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

    def disconnect(self, graceful=True):
        """
        Override of netmiko's disconnect(). Different: graceful=False closes the connection at
        once without writing to the line (no logout), is safe from another thread even while
        connecting, and opens nothing new until the next connect(). graceful=True runs netmiko's
        disconnect() as before. Either way, no TCP connection the object opened stays open.
        """
        with self._state_lock:
            self._connected = False
        if graceful:
            super(BaseConsoleConn, self).disconnect()
        with self._state_lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            # shutdown() ends the connection and wakes any thread blocked on it; close() alone does not.
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

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
