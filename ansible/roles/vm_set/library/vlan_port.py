#!/usr/bin/python

import re
import sys
import time
import subprocess
from pprint import pprint
from ansible.module_utils.basic import *

DOCUMENTATION = '''
module: vlan_port
version_added: "0.1"
author: Guohan Lu (gulv@microsoft.com)
short_description: Get/Create/Remove vlan tunnel port in the test server for physical DUT
'''

EXAMPLES = '''
- name: Set front panel port for vlan tunnel
  vlan_port:
    external_port: "{{ external_port }}"
    vlan_ids: "{{ device_vlan_list }}"
    cmd: "list"
'''

DOCUMENTATION = '''
    - external_port: external port
    - vlan_ids:      vlan list
'''

CMD_DEBUG_FNAME = '/tmp/vlan_port.cmds.txt'
EXCEPTION_DEBUG_FNAME = '/tmp/vlan_port.exception.txt'

class VlanPort(object):
    def __init__(self, external_port, vlan_ids):
        self.external_port = external_port
        self.vlan_ids = vlan_ids
        self.host_ifaces = VlanPort.ifconfig('ifconfig -a')

        return

    def up_external_port(self):
        if self.external_port in self.host_ifaces:
            VlanPort.iface_up(self.external_port)

        return

    def create_vlan_port(self, port, vlan_id):
        vlan_port = "%s.%d" % (port, vlan_id)
        if vlan_port not in self.host_ifaces:
            VlanPort.cmd('vconfig add %s %d' % (port, vlan_id))

        VlanPort.iface_up(vlan_port)

        return

    def destroy_vlan_port(self, vlan_port):
        if vlan_port in self.host_ifaces:
            VlanPort.iface_down(vlan_port)
            VlanPort.cmd('vconfig rem %s' % vlan_port)

        return

    def create_vlan_ports(self):
        for vlan_id in self.vlan_ids.values():
            self.create_vlan_port(self.external_port, vlan_id)

    def remove_vlan_ports(self):
        for vlan_id in self.vlan_ids.values():
            vlan_port = "%s.%d" % (self.external_port, vlan_id)
            self.destroy_vlan_port(vlan_port)

    @staticmethod
    def ifconfig(cmdline):
        out = VlanPort.cmd(cmdline)

        ifaces = set()

        rows = out.split('\n')
        for row in rows:
            if len(row) == 0:
                continue
            terms = row.split()
            if not row[0].isspace():
                ifaces.add(terms[0].rstrip(':'))

        return ifaces

    @staticmethod
    def iface_up(iface_name, pid=None):
        return VlanPort.iface_updown(iface_name, 'up', pid)

    @staticmethod
    def iface_down(iface_name, pid=None):
        return VlanPort.iface_updown(iface_name, 'down', pid)

    @staticmethod
    def iface_updown(iface_name, state, pid):
        if pid is None:
            return VlanPort.cmd('ip link set %s %s' % (iface_name, state))
        else:
            return VlanPort.cmd('nsenter -t %s -n ip link set %s %s' % (pid, iface_name, state))

    @staticmethod
    def cmd(cmdline):
        with open(CMD_DEBUG_FNAME, 'a') as fp:
            pprint("CMD: %s" % cmdline, fp)
        cmd = cmdline.split(' ')
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        ret_code = process.returncode

        if ret_code != 0:
            raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, cmdline))

        with open(CMD_DEBUG_FNAME, 'a') as fp:
            pprint("OUTPUT: %s" % stdout, fp)

        return stdout.decode('utf-8')


def main():

    module = AnsibleModule(argument_spec=dict(
        cmd=dict(required=True, choices=['create', 'remove', 'list']),
        external_port=dict(required=True, type='str'),
        vlan_ids=dict(required=True, type='dict'),
    ))

    cmd = module.params['cmd']
    external_port = module.params['external_port']
    vlan_ids = module.params['vlan_ids']

    fp_ports = {}

    vp = VlanPort(external_port, vlan_ids)

    vp.up_external_port()
    if cmd == "create":
        vp.create_vlan_ports()
    elif cmd == "remove":
        vp.remove_vlan_ports()

    fp_port_templ = external_port + ".%s"
    for a_port_index, vid in vlan_ids.items():
        fp_ports[a_port_index] = fp_port_templ % vid

    module.exit_json(changed=False, ansible_facts={'dut_fp_ports': fp_ports})


if __name__ == "__main__":
    main()
