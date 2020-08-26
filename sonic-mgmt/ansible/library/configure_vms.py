#!/usr/bin/python

DOCUMENTATION = '''
module:         configure_vms
version_added:  "1.0"
author:         Harsha Adiga (hadiga@linkedin.com)
short_description: This module configures the FAB switch (Arista VM) to add
                   loopback interface required to run FIB Acceleration test
                   cases
description:
    - This module configures the FAB switch (Arista VM) to add loopback
      interface required to run FIB Acceleration test cases
'''

EXAMPLES = '''
- name: Configure VMs to add loopback interface
  configure_vms: ip={{ item }}
'''

from ansible.module_utils.basic import *
import paramiko
import json
import time

class ConfigureVMs(object):
    def __init__(self, ip, cmds, module, login='admin', password='123456'):
        self.ip = ip
        self.cmds = cmds
        self.login = login
        self.password = password
        self.module = module
        self.conn = None

        self.facts = {}

    def __del__(self):
        self.disconnect()

    def connect(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.conn.connect(self.ip,
                          username=self.login,
                          password=self.password,
                          allow_agent=False,
                          look_for_keys=False)
        self.shell = self.conn.invoke_shell()

        return self.shell

    def do_cmd(self, cmd):
        if cmd is not None:
            self.shell.send(cmd + '\n')

        return

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

        return

    def run(self):
        self.connect()

        self.do_cmd('enable')
        time.sleep(1)

        for cmd in self.cmds:
            self.do_cmd(cmd)
            time.sleep(5)

        self.module.exit_json(ansible_facts={'conf_vm':self.facts})

        self.disconnect()

        return

def main():
    module = AnsibleModule(
        argument_spec=dict(
            ip=dict(required=True),
            cmds=dict(required=True),
            login=dict(required=False),
            password=dict(required=False)
        ),
        supports_check_mode=False)

    m_args = module.params
    ip = m_args['ip']
    cmds = m_args['cmds']
    login = m_args['login']
    password = m_args['password']

    conf = ConfigureVMs(ip, cmds, module)
    conf.run()

    return

if __name__ == "__main__":
    main()
