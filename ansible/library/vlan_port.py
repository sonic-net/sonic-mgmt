#!/usr/bin/python

import re
import sys
import time
import subprocess
from ansible.module_utils.basic import *

DOCUMENTATION = '''
    - vlan_base: the first vlan for the network
'''

class VlanPort(object):
    def __init__(self, external_port):
        self.external_port = external_port

        self.host_ifaces = VlanPort.ifconfig('ifconfig -a')

        return

    def init(self, vm_set_name, topo, vm_base, dut_fp_ports, ptf_exists=True):
        self.vm_set_name = vm_set_name
        if 'VMs' in topo:
            self.VMs = topo['VMs']
            self.vm_base = vm_base
            if vm_base in self.vm_names:
                self.vm_base_index = self.vm_names.index(vm_base)
            else:
                raise Exception('VM_base "%s" should be presented in current vm_names: %s' % (vm_base, str(self.vm_names)))
            for hostname, attrs in self.VMs.iteritems():
                vmname = self.vm_names[self.vm_base_index + attrs['vm_offset']]
                if len(attrs['vlans']) > len(self.get_bridges(vmname)):
                    raise Exception("Wrong vlans parameter for hostname %s, vm %s. Too many vlans. Maximum is %d" % (hostname, vmname, len(self.get_bridges(vmname))))
        else:
            self.VMs = {}
            
        if 'host_interfaces' in topo:
            self.host_interfaces = topo['host_interfaces']
        else:
            self.host_interfaces = []

        self.dut_fp_ports = dut_fp_ports

        self.injected_fp_ports = self.extract_vm_vlans()

        if ptf_exists:
            self.pid = VMTopology.get_pid(PTF_NAME_TEMPLATE % vm_set_name)
        else:
            self.pid = None

        self.update()

        return


    def up_external_port(self):
        if self.external_port in self.host_interfaces:
            VlanPort.iface_up(self.external_port)

        return

    def find_base_vlan(self):
        vlan_base = 0
        for attr in self.VMs.itervalues():
            vm_name = self.vm_names[self.vm_base_index + attr['vm_offset']]
            if len(attr['vlans']) > 0:
                br_name = OVS_FP_BRIDGE_TEMPLATE % (vm_name, 0)
                out = VlanPort.cmd('ovs-vsctl list-ports %s' % br_name)
                rows = out.split('\n')
                for row in rows:
                    if row.startswith(self.external_port):
                        extracted_vlan = int(row[len(self.external_port)+1:])
                        return extracted_vlan - attr['vlans'][0]
 
        raise Exception("Can't find previous vlan_base")

    def create_vlan_port(self, vlan_port, vlan_id):
        if vlan_port not in self.host_ifaces:
            VlanPort.cmd('vconfig add %s %d' % (self.external_port, vlan_id))

        VlanPort.iface_up(vlan_port)

        return

    def destroy_vlan_port(self, vlan_port):
        if vlan_port in self.host_ifaces:
            VlanPort.iface_down(vlan_port)
            VlanPort.cmd('vconfig rem %s' % vlan_port)

        return

    def create_vlan_ports():

        for attr in self.VMs.itervalues():
            for vlan_num, vlan in enumerate(attr['vlans']):
               vlan_id = self.vlan_base + vlan
               vlan_port = "%s.%d" % (self.external_port, vlan_id)

               self.create_vlan_port(vlan_port, vlan_id)

    def remove_vlan_ports():

        for attr in self.VMs.itervalues():
            for vlan_num, vlan in enumerate(attr['vlans']):
               vlan_id = self.vlan_base + vlan
               vlan_port = "%s.%d" % (self.external_port, vlan_id)

               self.destroy_vlan_port(vlan_port)

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
        return stdout

def main():

    module = AnsibleModule(argument_spec=dict(
        external_port = dict(required=True, type='str'),
        vlan_base=dict(required=True, type='int'),
    ))

    mgmt_port = None
    fp_ports = []

    vp.up_external_port()

            vlan_base = module.params['vlan_base']
    for l in output.split('\n'):
        fds = re.split('\s+', l)
        if len(fds) != 5:
            continue
        if fds[1] == "ethernet":
            if mgmt_port == None:
                mgmt_port = fds[0]
            else:
                fp_ports.append(fds[0])

    module.exit_json(changed=False, ansible_facts={'dut_mgmt_port': mgmt_port, 'dut_fp_ports': fp_ports})

if __name__ == "__main__":
    main()


