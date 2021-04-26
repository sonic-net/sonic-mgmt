import paramiko
from paramiko.py3compat import u
import termios
import tty
import select
import sys
import socket

class SSHClient(paramiko.client.SSHClient):
    """
    A subclass of paramiko's SSHClient.
    The 'connect' interface is overwrite to support multi passowrds.
    """
    def connect(self, hostname, username=None, passwords=None, port=22):
        """
        @summary: Overwrite 'connect' of SSHClient in paramiko to support multi passwords
        @param hostname: The hostname or IP of target host
        @param username: The username for SSH login
        @param passwords: Passwords for SSH login, a list of string
        """
        self.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for i in range(0, len(passwords)):
            password = passwords[i]
            try:
                super(SSHClient, self).connect(hostname=hostname, port=port, username=username, password=password)
            except paramiko.ssh_exception.AuthenticationException as e:
                if i == len(passwords) - 1:
                    raise e
                else:
                    continue
            else:
                break

    def run_command(self, cmd):
        """
        @summary: Run command in remote host (must be connected first)
        @param cmd: The command to run
        @return: A tuple contains 3 strings (stdin, stdout, stderr)
        """
        stdin, stdout, stderr = super(SSHClient, self).exec_command(cmd)

        def _read_stream(stream):
            return stream.read().decode().strip() if stream.readable() else ""

        return _read_stream(stdin), _read_stream(stdout), _read_stream(stderr)

    def posix_shell(self):
        """
        @summary: Open an interactive shell
        """
        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            chan = super(SSHClient, self).invoke_shell()
            chan.settimeout(0.0)

            while True:
                r, w, e = select.select([chan, sys.stdin], [], [])
                if chan in r:
                    try:
                        x = u(chan.recv(1024))
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
                    chan.send(x)

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

