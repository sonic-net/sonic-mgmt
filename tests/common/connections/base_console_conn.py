"""
Base class for console connection of SONiC devices
"""

import logging
from netmiko.cisco_base_connection import CiscoBaseConnection
from netmiko.ssh_exception import NetMikoAuthenticationException

# For interactive shell
import sys
import socket
from paramiko.py3compat import u
import termios
import tty
import select

# All supported console types
# Console login via telnet (mad console)
CONSOLE_TELNET = "console_telnet"
# Console login via SSH (digi)
CONSOLE_SSH = "console_ssh"
# Console login via SSH, then login to devices by 'menu ports'
CONSOLE_SSH_MENU_PORTS = "console_ssh_menu_ports"

class BaseConsoleConn(CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        # Clear additional args before passing to BaseConsoleConn
        all_passwords = kwargs['console_password']
        key_to_rm = ['console_username', 'console_password', 
                    'console_host', 'console_port',
                    'sonic_username', 'sonic_password',
                    'console_type']
        for key in key_to_rm:
            if kwargs.has_key(key):
                del kwargs[key]

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

    def disable_paging(self, command="", delay_factor=1):
        # not supported
        pass

    def find_prompt(self, delay_factor=1):
        return super(BaseConsoleConn, self).find_prompt(delay_factor)

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
                        x = u(self.remote_conn.recv(1024))
                        if len(x) == 0:
                            sys.stdout.write("\r\n*** EOF\r\n")
                            break
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
