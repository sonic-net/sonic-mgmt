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
        return 'onie'

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
        client = None

        cmd = self._ssh_command + ['-l', "root", self.host]
        client = pexpect.spawn(' '.join(cmd), env={'TERM': 'dumb'})
        client.expect(['#'])

        self.before_backup = client.before.split()

        return client

    def exec_command(self, *args, **kwargs):

        self.template = kwargs['template']
        if kwargs['host'] is not None:
            self.host     = kwargs['host']
        self.url      = kwargs['url']
        self.install  = kwargs['install']
        self.nretry   = kwargs['retry']

        self._build_command()

        client = self._spawn_connect()

        # Set command timeout after connection is spawned
        if kwargs['timeout']:
            client.timeout = int(kwargs['timeout'])

        prompts = ["ONIE:.+ #", pexpect.EOF]

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

        if self.install:
            client.sendline('onie-discovery-stop')
            client.expect(prompts)
            stdout += client.before
            attempt = 0
            while attempt < self.nretry:
                client.sendline("onie-nos-install %s" % self.url)
                i = client.expect(["Installed SONiC base image SONiC-OS successfully"] + prompts)
                stdout += client.before
                if i == 0:
                    break
                elif i == 1:
                    attempt += 1
                    self._display.vvv("Installation fails, retry %d..." % attempt, host=self.host)
                else:
                    raise AnsibleError("Failed to install sonic image. %s" % stdout)
            self._display.vvv("SONiC installed.", host=self.host)
            # for some platform, e.g., DELL S6000, it will do hard reboot,
            # which will not give EOF
            client.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=15)
            stdout += client.before
            self._display.vvv("ONIE Rebooted. %s" % stdout, host=self.host)

        return stdout

    def put_file(self, in_path, out_path):
        pass

    def fetch_file(self, in_path, out_path):
        pass

    def close(self):
        self._connected = False
