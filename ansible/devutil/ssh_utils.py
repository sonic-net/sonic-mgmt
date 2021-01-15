import paramiko
from paramiko.py3compat import u
import termios
import tty
import select
import sys
import socket

class SSHClient(paramiko.client.SSHClient):

    def connect(self, hostname, username=None, passwords=None, port=22):
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
        stdin, stdout, stderr = super(SSHClient, self).exec_command(cmd)
        return stdin.read().decode().strip() if stdin.readable() else "", \
               stdout.read().decode().strip() if stdout.readable() else "", \
               stderr.read().decode().strip() if stderr.readable() else ""

    def posix_shell(self):
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
