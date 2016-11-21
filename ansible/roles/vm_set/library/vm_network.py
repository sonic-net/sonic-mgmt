#!/usr/bin/python

import subprocess
import re
from docker import Client
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: vm_network_create
version_added: "0.1"
author: Pavel Shirshov (pavelsh@microsoft.com)
short_description: Generate virtual network for a set of VMs
description:
    - With cmd: 'create' the module:
      - creates 32*8 ovs bridges with name template "br-vs{{ vm_set_id }}-vm{{ vm_set_dict[]['num']}}-{{ 0..7 }}" which will be used by FP port of VMs
      - creates a linux bridge with name {{ port1_bridge }} for backplane connectivity between VMs
    - With cmd: 'destroy' the module:
      - destroys 32*8 ovs bridges with name template "br-vs{{ vm_set_id }}-vm{{ vm_set_dict[]['num']}}-{{ 0..7 }}" which were used by FP port of VMs
      - destroys a linux bridge with name {{ port1_bridge }} for backplane connectivity between VMs
    - With cmd: 'bind' the module:
      - creates 32 vlan interfaces on the external interface
      - bind this interfaces to the ovs bridges which were created by 'create' command
      - bind corresponing interface from ptf_injected container to the ovs bridges
    - With cmd: 'unbind' the module:
      - destroys 32 vlan interfaces from the external interface

Parameters:
    - cmd: One of the commands: 'create', 'bind', 'unbind', 'destroy'
    - vm_set_id: identifier for the VM set, a number
    - port1_bridge: name of the bridge which will be created for the backplane connectivity
    - vm_set_dict: dictionary with VM parameters. Check host_vars/STR-ACS-SERV-0x.yml for details
    - fp_mtu: MTU for FP ports
    - ext_iface: physical interface which will be used for for vlan creation
    - vlan_base: the first vlan for the network
'''

EXAMPLES = '''
- name: Create VM set network. vm set {{ id }}
  vm_network:
    cmd: 'create'
    vm_set_id: "{{ id }}"
    port1_bridge: "{{ port1_bridge }}"
    vm_set_dict: "{{ VMs }}"
    fp_mtu: "{{ fp_mtu_size }}"
    ext_iface: "{{ external_iface }}"
    vlan_base: "{{ vlan_base }}"
'''

DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 8
OVS_BRIDGE_TEMPLATE = 'br-vs%d-vm%d-%d'
INJECTED_INTERFACES_TEMPLATE = "inje-%d-%d"

class VMNetwork(object):

    def __init__(self, vm_set_id, port1_bridge, vm_set_dict, ext_iface, vlan_base, fp_mtu=DEFAULT_MTU):
        self.vm_set_id = vm_set_id
        self.port1_bridge = port1_bridge
        self.vm_set_dict = vm_set_dict
        self.ext_iface = ext_iface
        self.vlan_base = vlan_base
        self.fp_mtu = fp_mtu

        self.host_ifaces = VMNetwork.ifconfig('ifconfig -a')

        return

    def create_port1_bridge(self):
        if self.port1_bridge not in self.host_ifaces:
            VMNetwork.cmd('brctl addbr %s' % self.port1_bridge)

        VMNetwork.cmd('ifconfig %s up' % self.port1_bridge)

        return

    def destroy_port1_bridge(self):
        if self.port1_bridge in self.host_ifaces:
            VMNetwork.cmd('ifconfig %s down' % self.port1_bridge)
            VMNetwork.cmd('brctl delbr %s' % self.port1_bridge)

        return

    def create_fp_bridges(self):
        for vm in self.vm_set_dict.itervalues():
            for vlan_num in xrange(NUM_FP_VLANS_PER_FP):
                self.create_fp_bridge(vm["num"], vlan_num)

        return

    def create_fp_bridge(self, vm_num, vlan_num):
        vlan_name = OVS_BRIDGE_TEMPLATE % (self.vm_set_id, int(vm_num), vlan_num)

        if vlan_name not in self.host_ifaces:
            VMNetwork.cmd('ovs-vsctl add-br %s' % vlan_name)

        if self.fp_mtu != DEFAULT_MTU:
            VMNetwork.cmd('ifconfig %s mtu %d' % (vlan_name, self.fp_mtu))

        VMNetwork.cmd('ifconfig %s up' % vlan_name)

        return

    def destroy_fp_bridges(self):
        for vm in self.vm_set_dict.itervalues():
            for vlan_num in xrange(NUM_FP_VLANS_PER_FP):
                self.destroy_fp_bridge(vm["num"], vlan_num)

        return


    def destroy_fp_bridge(self, vm_num, vlan_num):
        vlan_name = OVS_BRIDGE_TEMPLATE % (self.vm_set_id, int(vm_num), vlan_num)

        if vlan_name in self.host_ifaces:
            VMNetwork.cmd('ifconfig %s down' % vlan_name)
            VMNetwork.cmd('ovs-vsctl del-br %s' % vlan_name)

        return

    def up_ext_iface(self):
        if self.ext_iface in self.host_ifaces:
            VMNetwork.cmd('ifconfig %s up' % self.ext_iface)

        return

    def check_vlans(self, vlans_str, vlans):
        if len(vlans) == 0:
           return

        if len(vlans) > 8:
           raise Exception("Wrong vlans parameter. Too many vlans. Maximum is 8: %s" % vlans_str)

        for vlan in vlans_str.split(','):
            if not vlan.isdigit():
                raise Exception("Wrong vlans parameter: %s" % vlans_str)

        for vlan in vlans:
            if int(vlan) > 31:
                raise Exception("Vlan offset %s supposed to be not more then 31: %s" % (vlan, vlans_str))

        return

    def bind(self):
        for vm in self.vm_set_dict.itervalues():
            vm_num = vm['num']
            vlans_str = vm['vlans']
            vlans = [int(vlan) for vlan in vlans_str.split(',')]
            self.check_vlans(vlans_str, vlans)
            for vlan_num, vlan in enumerate(vlans):
               vlan_id = self.vlan_base + vlan
               vlan_iface = "%s.%d" % (self.ext_iface, vlan_id)
               injected_iface = INJECTED_INTERFACES_TEMPLATE % (self.vm_set_id, vlan)
               port0_bridge = OVS_BRIDGE_TEMPLATE % (self.vm_set_id, int(vm_num), vlan_num)
               self.create_phys_vlan(vlan_iface, vlan_id)
               self.bind_phys_vlan(port0_bridge, vlan_iface, injected_iface)

        return

    def create_phys_vlan(self, vlan_iface, vlan_id):
        if vlan_iface not in self.host_ifaces:
            VMNetwork.cmd('vconfig add %s %d' % (self.ext_iface, vlan_id))

        VMNetwork.cmd('ifconfig %s up' % vlan_iface)

        return

    def bind_phys_vlan(self, br_name, vlan_iface, injected_iface):
        ports = VMNetwork.get_ovs_br_ports(br_name)

        if injected_iface not in ports:
            VMNetwork.cmd('ovs-vsctl add-port %s %s' % (br_name, injected_iface))

        if vlan_iface not in ports:
            VMNetwork.cmd('ovs-vsctl add-port %s %s' % (br_name, vlan_iface))

        bindings = VMNetwork.get_ovs_port_bindings(br_name)
        vlan_iface_id = bindings[vlan_iface]

        # clear old bindings
        VMNetwork.cmd('ovs-ofctl del-flows %s' % br_name)

        # Add flow from a VM to an external iface
        VMNetwork.cmd("ovs-ofctl add-flow %s table=0,in_port=1,action=output:%s" % (br_name, vlan_iface_id))

        # Add flow from external iface to a VM and a ptf container
        VMNetwork.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:1,2" % (br_name, vlan_iface_id))

        # Add flow from a ptf container to an external iface
        VMNetwork.cmd("ovs-ofctl add-flow %s table=0,in_port=2,action=output:%s" % (br_name, vlan_iface_id))

        return

    def unbind(self):
        # try vlans from the host_vars
        for vm in self.vm_set_dict.itervalues():
            vm_num = vm['num']
            vlans_str = vm['vlans']
            vlans = [int(vlan) for vlan in vlans_str.split(',')]
            self.check_vlans(vlans_str, vlans)
            for vlan_num, vlan in enumerate(vlans):
               vlan_id = self.vlan_base + vlan
               vlan_iface = "%s.%d" % (self.ext_iface, vlan_id)
               injected_iface = INJECTED_INTERFACES_TEMPLATE % (self.vm_set_id, vlan)
               port0_bridge = OVS_BRIDGE_TEMPLATE % (self.vm_set_id, int(vm_num), vlan_num)
               self.unbind_phys_vlan(port0_bridge, vlan_iface)
               self.destroy_phys_vlan(vlan_iface)

        # try vlans from the ovs db
        for vm in self.vm_set_dict.itervalues():
            vm_num = vm['num']
            for vlan_num in xrange(NUM_FP_VLANS_PER_FP):
                bridge_name = OVS_BRIDGE_TEMPLATE % (self.vm_set_id, int(vm_num), vlan_num)
                ports = VMNetwork.get_ovs_port_bindings(bridge_name)
                for port in ports.iterkeys():
                    if self.ext_iface in port:
                        self.unbind_phys_vlan(bridge_name, port)
                        self.destroy_phys_vlan(port)

        return

    def destroy_phys_vlan(self, vlan_iface):
        if vlan_iface in self.host_ifaces:
            VMNetwork.cmd('ifconfig %s down' % vlan_iface)
            VMNetwork.cmd('vconfig rem %s' % vlan_iface)

        return

    def unbind_phys_vlan(self, br_name, vlan_iface):
        ports = VMNetwork.get_ovs_br_ports(br_name)

        if vlan_iface in ports:
            VMNetwork.cmd('ovs-vsctl del-port %s %s' % (br_name, vlan_iface))

        return

    @staticmethod
    def cmd(cmdline):
        cmd = cmdline.split(' ')
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        ret_code = process.returncode

        if ret_code != 0:
            raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, cmdline))

        return stdout

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = VMNetwork.cmd('ovs-vsctl list-ports %s' % bridge)
        return set(out.split('\n'))

    @staticmethod
    def get_ovs_port_bindings(bridge):
        out = VMNetwork.cmd('ovs-ofctl show %s' % bridge)
        lines = out.split('\n')
        result = {}
        for line in lines:
            matched = re.match(r'^\s+(\S+)\((\S+)\):\s+addr:.+$', line)
            if matched:
                port_id = matched.group(1)
                iface_name = matched.group(2)
                result[iface_name] = port_id

        return result

    @staticmethod
    def ifconfig(cmdline):
        out = VMNetwork.cmd(cmdline)

        ifaces = set()

        rows = out.split('\n')
        for row in rows:
            if len(row) == 0:
                continue
            terms = row.split()
            if not row[0].isspace():
                ifaces.add(terms[0])

        return ifaces


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(required=True, choices=['create', 'bind', 'unbind', 'destroy']),
            vm_set_id=dict(required=True, type='int'),
            port1_bridge=dict(required=True, type='str'),
            vm_set_dict=dict(required=True, type='dict'),
            fp_mtu=dict(required=False, type='int', default=DEFAULT_MTU),
            ext_iface=dict(required=True, type='str'),
            vlan_base=dict(required=True, type='int')),
        supports_check_mode=False)

    cmd = module.params['cmd']
    vm_set_id = module.params['vm_set_id']
    port1_bridge = module.params['port1_bridge']
    vm_set_dict = module.params['vm_set_dict']
    fp_mtu = module.params['fp_mtu']
    ext_iface = module.params['ext_iface']
    vlan_base = module.params['vlan_base']

    try:
        net = VMNetwork(vm_set_id, port1_bridge, vm_set_dict, ext_iface, vlan_base, fp_mtu)
        if cmd == 'create':
            net.create_port1_bridge()
            net.create_fp_bridges()
        elif cmd == 'destroy':
            net.destroy_port1_bridge()
            net.destroy_fp_bridges()
        elif cmd == 'bind':
            net.up_ext_iface()
            net.bind()
        elif cmd == 'unbind':
            net.unbind()
        else:
            raise Exception("Got wrong cmd: %s. Ansible bug?" % cmd)

    except Exception as error:
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()

