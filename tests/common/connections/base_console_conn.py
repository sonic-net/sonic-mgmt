"""
Base class for console connection of SONiC devices
"""

import logging
import paramiko
import re
import time

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
# Console login via SSH, no stage 2 login (Digi Config Menu)
CONSOLE_SSH_DIGI_CONFIG = "console_ssh_digi_config"
# Console login via SSH, no stage 2 login (SONiC switch config)
CONSOLE_SSH_SONIC_CONFIG = "console_ssh_sonic_config"
# Console login via SSH, no stage 2 login (Cisco switch config)
CONSOLE_SSH_CISCO_CONFIG = "console_ssh_cisco_config"
# Console login via conserver
CONSOLE_CONSERVER = "console_conserver"


class BaseConsoleConn(CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        self.bmc_first_console_switch = bool(kwargs.pop('bmc_first_console_switch', False))
        # Clear additional args before passing to BaseConsoleConn
        all_passwords = kwargs['console_password']
        key_to_rm = ['console_username', 'console_password',
                     'console_host', 'console_port',
                     'sonic_username', 'sonic_password',
                     'console_type', 'console_device']
        for key in key_to_rm:
            if key in kwargs:
                del kwargs[key]

        # netmiko's fast_cli=True default silently sets global_delay_factor
        # to 0.1, which shrinks login polling budgets too tightly for
        # serial-console getty timing. Default it off; callers can still
        # opt in via kwargs.
        kwargs.setdefault('fast_cli', False)

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
            try:
                super(BaseConsoleConn, self).__init__(**kwargs)
            except NetMikoAuthenticationException as e:
                if i == len(all_passwords) - 1:
                    raise e
            else:
                break

    def set_base_prompt(self, pri_prompt_terminator='#',
                        alt_prompt_terminator='$', delay_factor=1):
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

    def prepare_bmc_first_console(self):
        """
        On BMC-first UART mux platforms, switch to CPU console before SONiC login.
        Shared by telnet and SSH console connection paths.
        """
        if not self.bmc_first_console_switch:
            return
        time.sleep(0.3)
        self.read_channel()
        self.switch_bmc_to_cpu_console()

    def switch_bmc_to_cpu_console(self):
        """
        Some platforms mux BMC UART before CPU; send Ctrl+U, digit 2, then Enter so SONiC login appears.
        """
        self.logger.info("Console mux: Ctrl+U, 2, Enter for CPU console")
        newline = getattr(self, "TELNET_RETURN", self.RETURN)
        self.write_channel("\x15")
        time.sleep(0.5)
        self.write_channel("2" + newline)
        time.sleep(0.5)
        self.write_channel(newline)
        output = ""
        deadline = time.time() + 10
        # Match telnet_login() prompt patterns plus SONiC boot banner text.
        cpu_console_pattern = re.compile(
            r"(?:user:|username|login|user name|assword|SONiC Software|Open Networking)",
            re.IGNORECASE,
        )
        while time.time() < deadline:
            chunk = self.read_channel()
            if chunk:
                output += chunk
                if cpu_console_pattern.search(chunk):
                    break
            else:
                time.sleep(0.2)
        if output:
            self.logger.info(
                "Console mux response (first 500 chars): %r",
                output[:500],
            )
        else:
            self.logger.warning(
                "Console mux: no UART output within 10s after CPU switch"
            )

    def disable_paging(self, command="", delay_factor=1):
        # not supported
        pass

    def find_prompt(self, delay_factor=1, **kwargs):
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
