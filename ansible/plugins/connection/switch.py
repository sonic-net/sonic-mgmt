from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import subprocess
import shlex
import pipes
import pexpect
import random
import select
import fcntl
import pwd
import time

from ansible import constants as C
from ansible.errors import AnsibleError, AnsibleConnectionFailure, AnsibleFileNotFound
from ansible.plugins.connection import ConnectionBase

class Connection(ConnectionBase):
    ''' ssh based connections with expect '''

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)

        self.host = self._play_context.remote_addr
        self.connection_retry_interval = 60

    @property
    def transport(self):
        ''' used to identify this connection object from other classes '''
        return 'cisco'

    # The connection is created by running expect from the exec_command, so we don't
    # need to do any connection management here.

    def _connect(self):
        self._connect = True
        return self

    def _build_command(self):
        self._ssh_command = ['ssh', '-tt', '-q']
        ansible_ssh_args = C.ANSIBLE_SSH_ARGS
        if ansible_ssh_args:
            self._ssh_command += shlex.split(ansible_ssh_args)
        else:
            self._ssh_command += ['-o', 'ControlMaster=auto',
                                  '-o', 'ControlPersist=60s',
                                  '-o', 'ControlPath=/tmp/ansible-ssh-%h-%p-%r']

        if not C.HOST_KEY_CHECKING:
            self._ssh_command += ['-o', 'StrictHostKeyChecking=no']
            self._ssh_command += ['-o', 'UserKnownHostsFile=/dev/null']

        self._ssh_command += ['-o', 'GSSAPIAuthentication=no',
                              '-o', 'PubkeyAuthentication=no']
        self._ssh_command += ['-o', 'ConnectTimeout=30']

    def _spawn_connect(self):
        last_user = None
        client = None
        attempt = 0

        self._display.vvv("%s" % self.login)

        while attempt < len(self.login['user']):
            (user, login_passwd) = self.login['user'][attempt]
            if user != last_user:
                if client:
                    client.close()
                cmd = self._ssh_command + ['-l', user, self.host]
                self._display.vvv("SSH: EXEC {0}".format(' '.join(cmd)),
                              host=self.host)
                last_user = user
                client = pexpect.spawn(' '.join(cmd), env={'TERM': 'dumb'})
                i = client.expect(['[Pp]assword:', pexpect.EOF])
                if i == 1:
                    self._display.vvv("Server closed the connection, retry in %d seconds" % self.connection_retry_interval, host=self.host)
                    time.sleep(self.connection_retry_interval)
                    last_user = None
                    continue

            self._display.vvv("Try password %s..." % login_passwd[0:4], host=self.host)
            client.sendline(login_passwd)
            i = client.expect(['>', '#', '[Pp]assword:', pexpect.EOF])
            if i < 2:
                break
            elif i == 3:
                last_user = None

            # try a new password
            attempt += 1

        if attempt == len(self.login['user']):
            raise AnsibleError("none of the passwords in the book works")

        self.before_backup = client.before.split()

        # determine the sku
        client.sendline('show version')
        client.expect(['#', '>'])
        if 'Arista' in client.before:
            self.sku = 'eos'
        elif 'Cisco' in client.before:
            self.sku = 'nxos'
        if 'MLNX-OS' in client.before:
            self.sku = 'mlnx_os'
        if 'Dell' in client.before:
            self.sku = 'dell'

        if self.sku == 'mlnx_os':
            self.hname = ' '.join(self.before_backup[-3:])
            self.hname = self.hname.replace("(", "[(]")
            self.hname = self.hname.replace(")", "[)]")
            self.hname = self.hname.replace("]", "\]")
            self.hname = self.hname.replace("[", "\[")
        else:
            self.hname = self.before_backup[-1]
            self.hname = self.hname.replace("(", "[(]")
            self.hname = self.hname.replace(")", "[)]")

        if i == 0 and self.enable:
            attempt = 0
            client.sendline('enable')
            self.login['enable'].reverse()
            while True:
                i = client.expect(['#', '[Pp]assword:', '>'])
                if i == 1:
                    if attempt < len(self.login['enable']):
                        passwd = self.login['enable'][attempt]
                        client.sendline(passwd)
                        self._display.vvv("Try enable password %s..." % passwd[0:4], host=self.host)
                        attempt += 1
                    else:
                        raise AnsibleError("none of the enable passwords works")
                elif i == 2:
                    client.sendline('enable')
                else:
                    break

        if self.bash:
            if not self.enable:
                raise AnsibleError("can only get into bash with enable")

            if self.sku == "nxos":
                self._display.vvv("Enable configure mode", host=self.host)
                client.sendline('conf t')
                client.expect(['\(config\)#'])
                self._display.vvv("Enable bash feature", host=self.host)
                client.sendline('feature bash')
                client.expect(['\(config\)#'])
                client.sendline('run bash')
                self._display.vvv("Run bash", host=self.host)
                client.expect(['bash-\d.\d\$'])
                if self.su:
                    if user != 'admin':
                        raise AnsibleError("can only get into bash using local admin account")
                    client.sendline('sudo su root')
                    i = client.expect(['Password:', 'bash-\d.\d#'])
                    if i == 0:
                        self._display.vvv("Provide sudo password", host=self.host)
                        client.sendline(login_passwd)
                        client.expect(['bash-\d.\d#'])
                    self._display.vvv("Entered bash with root", host=self.host)
                else:
                    self._display.vvv("Entered bash", host=self.host)
            elif self.sku == "eos":
                client.sendline('bash')
                client.expect(['\$ '])
            else:
                raise AnsibleError("do not support shell mode for sku %s" % self.sku)

        return client

    def exec_command(self, *args, **kwargs):

        self.template = kwargs['template']
        if kwargs['host'] is not None:
            self.host     = kwargs['host']
        self.login    = kwargs['login']
        self.enable   = kwargs['enable']
        self.bash     = kwargs['bash']
        self.su       = kwargs['su']
        self.reboot   = kwargs['reboot']
        if kwargs['root']:
            self.login['user'] = 'root'
        self._build_command()

        client = self._spawn_connect()

        # Set command timeout after connection is spawned
        if kwargs['timeout']:
            client.timeout = int(kwargs['timeout'])

        # "%s>": non privileged prompt
        # "%s(\([a-z\-]+\))?#": privileged prompt including configure mode
        # Prompt includes Login, Password, and yes/no for "start shell" case in Dell FTOS (launch bash shell)
        if not self.bash:
            prompts = ["%s>" % self.hname, "%s.+" % self.hname, "%s(\([a-zA-Z0-9\/\-]+\))?#" % self.hname, '[Ll]ogin:', '[Pp]assword:', '\[(confirm )?yes\/no\]:', '\(y\/n\)\??\s?\[n\]']
        else:
            if self.sku == 'nxos':
                # bash-3.2$ for nexus 6.5
                prompts = ['bash-3\.2\$', 'bash-3\.2#']
            elif self.sku == 'eos':
                prompts = ['\$ ']

        prompts.append(pexpect.EOF)

        stdout = ""
        if self.template:
            cmds = self.template.split('\n')
        else:
            cmds = []
        for cmd in cmds:
            self._display.vvv('> %s' % (cmd), host=self.host)
            client.sendline(cmd)
            client.expect(prompts)
            stdout += client.before
            self._display.vvv('< %s' % (client.before), host=self.host)

        if self.reboot:
            if not self.enable:
                raise AnsibleError("can only reboot the box in enable mode")
            client.sendline('reload')
            # Proceed with reload\? \[confirm\] : EOS
            i = client.expect(['\(y\/n\)\??\s*\[n\]', 'Proceed with reload\? \[confirm\]', 'System configuration has been modified. Save\? \[yes\/no\/cancel\/diff\]:'])
            if i == 2:
                # EOS behavior
                stdout += client.before
                client.sendline('n')
                i = client.expect('Proceed with reload\? \[confirm\]')
            stdout += client.before
            client.sendline('y')
            # The system is going down for reboot NOW: EOS
            i = client.expect(['>', '#', 'The system is going down for reboot NOW', pexpect.TIMEOUT, pexpect.EOF])
            stdout += client.before
            if i < 2:
                raise AnsibleError("Box failed to reboot. stdout = %s" % stdout)
            self._display.vvv("Box rebooted", host=self.host)

        return stdout

    def put_file(self, in_path, out_path):
        pass

    def fetch_file(self, in_path, out_path):
        pass

    def close(self):
        self._connected = False
