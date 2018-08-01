#!/usr/bin/python

import subprocess
import re
import os
import os.path
import re
from docker import Client
from ansible.module_utils.basic import *
import traceback
from pprint import pprint

DOCUMENTATION = '''
---
module: vm_topology
version_added: "0.1"
author: Pavel Shirshov (pavelsh@microsoft.com)
short_description: Create a custom virtual topology for vm_sets
description:
    - With cmd: 'create' the module:
      - creates a bridges for every VM name in vm_names which will be used for back plane connections
      - creates len(vm_names)*max_fp_num ovs bridges with name template "br-{{ vm_name }}-{{ 0..max_fp_num-1 }}" which will be used by FP port of VMs
    - With cmd: 'destroy' the module:
      - destroys ovs bridges which were created with 'create' cmd
    - With cmd: 'bind' the module:
      - inserts mgmt interface inside of the docker container with name "ptf_{{vm_set_name}}"
      - assigns ip address and default route to the mgmt interface
      - inserts physical vlans into the docker container to represent endhosts
      - binds internal interfaces of the docker container to correspoinding VM ports
      - connects interfaces "Ethernet9" of every VM in current vm set to each other
      - connect vlan interface to bridges representing vm set fp ports
    - with cmd: 'renumber' the module:
      - disconnect vlan interface to bridges representing vm set fp ports
      - inserts mgmt interface inside of the docker container with name "ptf_{{vm_set_name}}"
      - assigns ip address and default route to the mgmt interface
      - inserts physical vlans into the docker container to represent endhosts
      - binds internal interfaces of the docker container to correspoinding VM ports
    - With cmd: 'unbind' the module:
      - destroys everything what was created with command 'bind'
    - With cmd: 'connect-vms' the module:
      - disconnect all VM ports from the DUT
    - With cmd: 'disconnect-vms' the module:
      - reconnect all VM ports to the DUT


Parameters:
    - cmd: One of the commands: 'create', 'bind', 'renumber', 'unbind', 'destroy', 'connect-vms', 'disconnect-vms'
    - vm_set_name: name of the current vm set. It will be used for generation of interface names
    - topo: dictionary with VMs topology. Check vars/topo_*.yml for details
    - vm_names: list of VMs represented on a current host
    - vm_base: which VM consider the first VM in the current vm set
    - vlan_base: the first vlan for the network
    - mgmt_ip_addr: ip address with prefixlen for the injected docker container
    - mgmt_ip_gw: default gateway for the injected docker container
    - mgmt_bridge: a bridge which is used as mgmt bridge on the host
    - ext_iface: physical interface which will be used for for vlan creation
    - fp_mtu: MTU for FP ports
'''

EXAMPLES = '''
- name: Create VMs network
  vm_network:
    cmd:          'create'
    vm_names:     "{{ VM_hosts }}"
    fp_mtu:       "{{ fp_mtu_size }}"

- name: Bind topology {{ topo }} to VMs. base vm = {{ VM_base }} base vlan = {{ vlan_base }}
  vm_topology:
    cmd: "bind"
    vm_set_name: "{{ vm_set_name }}"
    topo: "{{ topology }}"
    vm_names: "{{ VM_hosts }}"
    vm_base: "{{ VM_base }}"
    vlan_base: "{{ vlan_base }}"
    mgmt_ip_addr: "{{ ptf_ip }}"
    mgmt_ip_gw: "{{ mgmt_gw }}"
    mgmt_bridge: "{{ mgmt_bridge }}"
    ext_iface: "{{ external_iface }}"
    fp_mtu: "{{ fp_mtu_size }}"
    max_fp_num: "{{ max_fp_num }}
'''


DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 4
VM_SET_NAME_MAX_LEN = 8  # used in interface names. So restricted
MGMT_BR_NAME = 'mgmt'
CMD_DEBUG_FNAME = '/tmp/vmtopology.cmds.txt'
EXCEPTION_DEBUG_FNAME = '/tmp/vmtopology.exception.txt'

OVS_FP_BRIDGE_REGEX = 'br-%s-\d+'
OVS_FP_BRIDGE_TEMPLATE = 'br-%s-%d'
OVS_FP_TAP_TEMPLATE = '%s-t%d'
OVS_BRIDGE_BACK_TEMPLATE = 'br-%s-back'
INJECTED_INTERFACES_TEMPLATE = 'inje-%s-%d'
PTF_NAME_TEMPLATE = 'ptf_%s'
PTF_MGMT_IF_TEMPLATE = 'ptf-%s-m'
ROOT_BACK_BR_TEMPLATE = 'br-b-%s'
PTF_FP_IFACE_TEMPLATE = 'eth%d'
BACK_ROOT_END_IF_TEMPLATE = 'veth-bb-%s'
BACK_VM_END_IF_TEMPLATE = 'veth-bv-%s'
RETRIES = 3


class VMTopology(object):

    def __init__(self, vm_names, fp_mtu, max_fp_num):
        self.vm_names = vm_names
        self.fp_mtu = fp_mtu
        self.max_fp_num = max_fp_num

        self.host_ifaces = VMTopology.ifconfig('ifconfig -a')

        return

    def init(self, vm_set_name, topo, vm_base, vlan_base, ext_iface, ptf_exists=True):
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

        self.vlan_base = vlan_base
        self.ext_iface = ext_iface

        self.injected_fp_ports = self.extract_vm_vlans()

        if ptf_exists:
            self.pid = VMTopology.get_pid(PTF_NAME_TEMPLATE % vm_set_name)
        else:
            self.pid = None

        self.update()

        return

    def update(self):
        self.host_br_to_ifs, self.host_if_to_br = VMTopology.brctl('brctl show')
        self.host_ifaces = VMTopology.ifconfig('ifconfig -a')
        if self.pid is not None:
            self.ctr_ifaces = VMTopology.ifconfig('nsenter -t %s -n ifconfig -a' % self.pid)
        else:
            self.ctr_ifaces = None

        return

    def extract_vm_vlans(self):
        vlans = []
        for attr in self.VMs.itervalues():
            vlans.extend(attr['vlans'])

        return vlans

    def create_bridges(self):
        for vm in self.vm_names:
            for vlan_num in xrange(self.max_fp_num):
                vlan_br_name = OVS_FP_BRIDGE_TEMPLATE % (vm, vlan_num)
                self.create_bridge(vlan_br_name)
            port1_br_name = OVS_BRIDGE_BACK_TEMPLATE = 'br-%s-back' % vm
            self.create_bridge(port1_br_name)

        return

    def create_bridge(self, vlan_name):
        if vlan_name not in self.host_ifaces:
            VMTopology.cmd('ovs-vsctl add-br %s' % vlan_name)

        if self.fp_mtu != DEFAULT_MTU:
            VMTopology.cmd('ifconfig %s mtu %d' % (vlan_name, self.fp_mtu))

        VMTopology.cmd('ifconfig %s up' % vlan_name)

        return

    def destroy_bridges(self):
        for vm in self.vm_names:
            for ifname in self.host_ifaces:
                if re.compile(OVS_FP_BRIDGE_REGEX % vm).match(ifname):
                    self.destroy_bridge(ifname)
            port1_br_name = OVS_BRIDGE_BACK_TEMPLATE = 'br-%s-back' % vm
            self.destroy_bridge(port1_br_name)

        return

    def destroy_bridge(self, bridge_name):
        if bridge_name in self.host_ifaces:
            VMTopology.cmd('ifconfig %s down' % bridge_name)
            VMTopology.cmd('ovs-vsctl del-br %s' % bridge_name)

        return

    def get_bridges(self, vmname):
        brs = []
        for ifname in self.host_ifaces:
            if re.compile(OVS_FP_BRIDGE_REGEX % vmname).match(ifname):
                brs.append(ifname)

        return brs

    def add_veth_ports_to_docker(self):
        for vlan in self.injected_fp_ports:
            ext_if = INJECTED_INTERFACES_TEMPLATE % (self.vm_set_name, vlan)
            int_if = PTF_FP_IFACE_TEMPLATE % vlan
            self.add_veth_if_to_docker(ext_if, int_if)

        return

    def add_mgmt_port_to_docker(self, mgmt_bridge, mgmt_ip, mgmt_gw):
        self.add_br_if_to_docker(mgmt_bridge, PTF_MGMT_IF_TEMPLATE % self.vm_set_name, MGMT_BR_NAME)
        self.add_ip_to_docker_if(MGMT_BR_NAME, mgmt_ip, mgmt_gw)

        return

    def add_br_if_to_docker(self, bridge, ext_if, int_if):
        self.update()

        if ext_if not in self.host_ifaces:
            VMTopology.cmd("ip link add %s type veth peer name %s" % (ext_if, int_if))

        if ext_if not in self.host_if_to_br:
            VMTopology.cmd("brctl addif %s %s" % (bridge, ext_if))

        VMTopology.iface_up(ext_if)

        self.update()
        if int_if in self.host_ifaces and int_if not in self.ctr_ifaces:
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, int_if))

        VMTopology.iface_up(int_if, self.pid)

        return

    def add_ip_to_docker_if(self, int_if, mgmt_ip_addr, mgmt_gw):
        self.update()
        if int_if in self.ctr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip addr flush dev %s" % (self.pid, int_if))
            VMTopology.cmd("nsenter -t %s -n ip addr add %s dev %s" % (self.pid, mgmt_ip_addr, int_if))
            VMTopology.cmd("nsenter -t %s -n ip route add default via %s dev %s" % (self.pid, mgmt_gw, int_if))

        return

    def add_phy_if_to_docker(self, iface_name, vlan):
        int_if = "%s.%d" % (self.ext_iface, vlan)

        if int_if not in self.host_ifaces and iface_name not in self.ctr_ifaces and int_if not in self.ctr_ifaces:
            VMTopology.cmd("vconfig add %s %s" % (self.ext_iface, vlan))

        self.update()
        if int_if in self.host_ifaces and int_if not in self.ctr_ifaces and iface_name not in self.ctr_ifaces:
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, int_if))

        self.update()
        if int_if in self.ctr_ifaces and iface_name not in self.ctr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, int_if, iface_name))

        VMTopology.iface_up(iface_name, self.pid)

        return

    def add_veth_if_to_docker(self, ext_if, int_if):
        self.update()

        t_int_if = int_if + '_t'
        if ext_if not in self.host_ifaces:
            VMTopology.cmd("ip link add %s type veth peer name %s" % (ext_if, t_int_if))

        self.update()

        if self.fp_mtu != DEFAULT_MTU:
            VMTopology.cmd("ip link set dev %s mtu %d" % (ext_if, self.fp_mtu))
            if t_int_if in self.host_ifaces:
                VMTopology.cmd("ip link set dev %s mtu %d" % (t_int_if, self.fp_mtu))
            elif t_int_if in self.ctr_ifaces:
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, t_int_if, self.fp_mtu))
            elif int_if in self.ctr_ifaces:
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_if, self.fp_mtu))

        VMTopology.iface_up(ext_if)

        self.update()

        if t_int_if in self.host_ifaces and t_int_if not in self.ctr_ifaces and int_if not in self.ctr_ifaces:
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, t_int_if))

        self.update()

        if t_int_if in self.ctr_ifaces and int_if not in self.ctr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_if, int_if))

        VMTopology.iface_up(int_if, self.pid)

        return

    def up_ext_iface(self):
        if self.ext_iface in self.host_interfaces:
            VMTopology.iface_up(self.ext_iface)

        return

    def bind_fp_ports(self, disconnect_vm=False):
        for attr in self.VMs.itervalues():
            for vlan_num, vlan in enumerate(attr['vlans']):
               vlan_id = self.vlan_base + vlan
               vlan_iface = "%s.%d" % (self.ext_iface, vlan_id)
               injected_iface = INJECTED_INTERFACES_TEMPLATE % (self.vm_set_name, vlan)
               port0_bridge = OVS_FP_BRIDGE_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               vm_tap = OVS_FP_TAP_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               self.create_phys_vlan(vlan_iface, vlan_id)
               self.bind_phys_vlan(port0_bridge, vlan_iface, injected_iface, vm_tap, disconnect_vm)

        return

    def unbind_fp_ports(self):
        for attr in self.VMs.itervalues():
            for vlan_num, vlan in enumerate(attr['vlans']):
               vlan_id = self.vlan_base + vlan
               vlan_iface = "%s.%d" % (self.ext_iface, vlan_id)
               injected_iface = INJECTED_INTERFACES_TEMPLATE % (self.vm_set_name, vlan)
               port0_bridge = OVS_FP_BRIDGE_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               self.unbind_phys_vlan(port0_bridge, injected_iface)
               self.unbind_phys_vlan(port0_bridge, vlan_iface)
               self.destroy_phys_vlan(vlan_iface)

        return

    def bind_vm_backplane(self):
        root_back_bridge = ROOT_BACK_BR_TEMPLATE % self.vm_set_name

        if root_back_bridge not in self.host_ifaces:
            VMTopology.cmd('ovs-vsctl add-br %s' % root_back_bridge)

        VMTopology.iface_up(root_back_bridge)

        for attr in self.VMs.itervalues():
            vm_name = self.vm_names[self.vm_base_index + attr['vm_offset']]
            br_name = OVS_BRIDGE_BACK_TEMPLATE % vm_name

            back_int_name = BACK_ROOT_END_IF_TEMPLATE % vm_name
            vm_int_name = BACK_VM_END_IF_TEMPLATE % vm_name

            if back_int_name not in self.host_ifaces:
                VMTopology.cmd("ip link add %s type veth peer name %s" % (back_int_name, vm_int_name))

            if vm_int_name not in VMTopology.get_ovs_br_ports(br_name):
                VMTopology.cmd("ovs-vsctl add-port %s %s" % (br_name, vm_int_name))

            if back_int_name not in VMTopology.get_ovs_br_ports(root_back_bridge):
                VMTopology.cmd("ovs-vsctl add-port %s %s" % (root_back_bridge, back_int_name))

            VMTopology.iface_up(vm_int_name)
            VMTopology.iface_up(back_int_name)

        return

    def unbind_vm_backplane(self):
        root_back_bridge = ROOT_BACK_BR_TEMPLATE % self.vm_set_name

        if root_back_bridge in self.host_ifaces:
            VMTopology.iface_down(root_back_bridge)
            VMTopology.cmd('ovs-vsctl del-br %s' % root_back_bridge)

        for attr in self.VMs.itervalues():
            vm_name = self.vm_names[self.vm_base_index + attr['vm_offset']]
            br_name = OVS_BRIDGE_BACK_TEMPLATE % vm_name

            back_int_name = BACK_ROOT_END_IF_TEMPLATE % vm_name
            vm_int_name = BACK_VM_END_IF_TEMPLATE % vm_name

            self.unbind_phys_vlan(br_name, vm_int_name)

            if back_int_name in self.host_ifaces:
                VMTopology.iface_down(back_int_name)
                VMTopology.cmd("ip link delete dev %s" % back_int_name)

        return


    def create_phys_vlan(self, vlan_iface, vlan_id):
        if vlan_iface not in self.host_ifaces:
            VMTopology.cmd('vconfig add %s %d' % (self.ext_iface, vlan_id))

        VMTopology.iface_up(vlan_iface)

        return

    def bind_phys_vlan(self, br_name, vlan_iface, injected_iface, vm_iface, disconnect_vm=False):
        ports = VMTopology.get_ovs_br_ports(br_name)

        if injected_iface not in ports:
            VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, injected_iface))

        if vlan_iface not in ports:
            VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, vlan_iface))

        bindings = VMTopology.get_ovs_port_bindings(br_name, vlan_iface)
        vlan_iface_id = bindings[vlan_iface]
        injected_iface_id = bindings[injected_iface]
        vm_iface_id = bindings[vm_iface]

        # clear old bindings
        VMTopology.cmd('ovs-ofctl del-flows %s' % br_name)

        if disconnect_vm:
            # Drop packets from VM
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=drop" % (br_name, vm_iface_id))
        else:
            # Add flow from a VM to an external iface
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, vm_iface_id, vlan_iface_id))

        if disconnect_vm:
            # Add flow from external iface to ptf container
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, vlan_iface_id, injected_iface_id))
        else:
            # Add flow from external iface to a VM and a ptf container
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s,%s" % (br_name, vlan_iface_id, vm_iface_id, injected_iface_id))

        # Add flow from a ptf container to an external iface
        VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, injected_iface_id, vlan_iface_id))

        return

    def unbind_phys_vlan(self, br_name, vlan_iface):
        ports = VMTopology.get_ovs_br_ports(br_name)

        if vlan_iface in ports:
            VMTopology.cmd('ovs-vsctl del-port %s %s' % (br_name, vlan_iface))

        return

    def inject_host_ports(self):
        self.update()
        for vlan in self.host_interfaces:
            self.add_phy_if_to_docker(PTF_FP_IFACE_TEMPLATE % vlan, self.vlan_base + vlan)

        return

    def destroy_phys_vlan(self, vlan_iface):
        if vlan_iface in self.host_ifaces:
            VMTopology.iface_down(vlan_iface)
            VMTopology.cmd('vconfig rem %s' % vlan_iface)

        return

    @staticmethod
    def iface_up(iface_name, pid=None):
        return VMTopology.iface_updown(iface_name, 'up', pid)

    @staticmethod
    def iface_down(iface_name, pid=None):
        return VMTopology.iface_updown(iface_name, 'down', pid)

    @staticmethod
    def iface_updown(iface_name, state, pid):
        if pid is None:
            return VMTopology.cmd('ip link set %s %s' % (iface_name, state))
        else:
            return VMTopology.cmd('nsenter -t %s -n ip link set %s %s' % (pid, iface_name, state))

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

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = VMTopology.cmd('ovs-vsctl list-ports %s' % bridge)
        return set(out.split('\n'))


    @staticmethod
    def get_ovs_port_bindings(bridge, vlan_iface = None):
        # Vlan interface addition may take few secs to reflect in OVS Command,
        # Let`s retry few times in that case.
        for retries in range(RETRIES):
            out = VMTopology.cmd('ovs-ofctl show %s' % bridge)
            lines = out.split('\n')
            result = {}
            for line in lines:
                matched = re.match(r'^\s+(\S+)\((\S+)\):\s+addr:.+$', line)
                if matched:
                    port_id = matched.group(1)
                    iface_name = matched.group(2)
                    result[iface_name] = port_id
            # Check if we have vlan_iface populated
            if vlan_iface is None or vlan_iface in result:
                return result
            time.sleep(2*retries+1)
        # Flow reaches here when vlan_iface not present in result 
        raise Exception("Can't find vlan_iface_id")

    @staticmethod
    def ifconfig(cmdline):
        out = VMTopology.cmd(cmdline)

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
    def get_pid(ptf_name):
        cli = Client(base_url='unix://var/run/docker.sock')
        result = cli.inspect_container(ptf_name)

        return result['State']['Pid']

    @staticmethod
    def brctl(cmdline):
        out = VMTopology.cmd(cmdline)

        br_to_ifs = {}
        if_to_br = {}

        rows = out.split('\n')[1:]
        cur_br = None
        for row in rows:
            if len(row) == 0:
                continue
            terms = row.split()
            if not row[0].isspace():
                cur_br = terms[0]
                br_to_ifs[cur_br] = []
                if len(terms) > 3:
                    br_to_ifs[cur_br].append(terms[3])
                    if_to_br[terms[3]] = cur_br
            else:
                br_to_ifs[cur_br].append(terms[0])
                if_to_br[terms[0]] = cur_br

        return br_to_ifs, if_to_br

    def find_base_vlan(self):
        vlan_base = 0
        for attr in self.VMs.itervalues():
            vm_name = self.vm_names[self.vm_base_index + attr['vm_offset']]
            if len(attr['vlans']) > 0:
                br_name = OVS_FP_BRIDGE_TEMPLATE % (vm_name, 0)
                out = VMTopology.cmd('ovs-vsctl list-ports %s' % br_name)
                rows = out.split('\n')
                for row in rows:
                    if row.startswith(self.ext_iface):
                        extracted_vlan = int(row[len(self.ext_iface)+1:])
                        return extracted_vlan - attr['vlans'][0]
 
        raise Exception("Can't find previous vlan_base")

def check_topo(topo):
    hostif_exists = False
    vms_exists = False
    all_vlans = set()

    if 'host_interfaces' in topo:
        vlans = topo['host_interfaces']

        if not isinstance(vlans, list):
            raise Exception("topo['host_interfaces'] should be a list of integers")

        for vlan in vlans:
            if not isinstance(vlan, int) or vlan < 0:
                raise Exception("topo['host_interfaces'] should be a list of integers")
            if vlan in all_vlans:
                raise Exception("topo['host_interfaces'] double use of vlan: %d" % vlan)
            else:
                all_vlans.add(vlan)

        hostif_exists = True

    if 'VMs' in topo:
        VMs = topo['VMs']

        if not isinstance(VMs, dict):
            raise Exception("topo['VMs'] should be a dictionary")

        for hostname, attrs in VMs.iteritems():
            if 'vlans' not in attrs or not isinstance(attrs['vlans'], list):
                raise Exception("topo['VMs']['%s'] should contain 'vlans' with a list of vlans" % hostname)

            if 'vm_offset' not in attrs or not isinstance(attrs['vm_offset'], int):
                raise Exception("topo['VMs']['%s'] should contain 'vm_offset' with a number" % hostname)

            for vlan in attrs['vlans']:
                if not isinstance(vlan, int) or vlan < 0:
                    raise Exception("topo['VMs'][%s]['vlans'] should contain a list with integers" % hostname)
                if vlan in all_vlans:
                    raise Exception("topo['VMs'][%s]['vlans'] double use of vlan: %d" % (hostname, vlan))
                else:
                    all_vlans.add(vlan)

        vms_exists = True

    return hostif_exists, vms_exists

def check_params(module, params, mode):
    for param in params:
        if param not in module.params:
            raise Exception("Parameter %s is required in %s mode" % (param, mode))

    return

def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(required=True, choices=['create', 'bind', 'renumber', 'unbind', 'destroy', "connect-vms", "disconnect-vms"]),
            vm_set_name=dict(required=False, type='str'),
            topo=dict(required=False, type='dict'),
            vm_names=dict(required=True, type='list'),
            vm_base=dict(required=False, type='str'),
            vlan_base=dict(required=False, type='int'),
            mgmt_ip_addr=dict(required=False, type='str'),
            mgmt_ip_gw=dict(required=False, type='str'),
            mgmt_bridge=dict(required=False, type='str'),
            ext_iface=dict(required=False, type='str'),
            fp_mtu=dict(required=False, type='int', default=DEFAULT_MTU),
            max_fp_num=dict(required=False, type='int', default=NUM_FP_VLANS_PER_FP),
        ),
        supports_check_mode=False)

    cmd = module.params['cmd']
    vm_names = module.params['vm_names']
    fp_mtu = module.params['fp_mtu']
    max_fp_num = module.params['max_fp_num']

    try:
        if os.path.exists(CMD_DEBUG_FNAME) and os.path.isfile(CMD_DEBUG_FNAME):
            os.remove(CMD_DEBUG_FNAME)

        net = VMTopology(vm_names, fp_mtu, max_fp_num)

        if cmd == 'create':
            net.create_bridges()
        elif cmd == 'destroy':
            net.destroy_bridges()
        elif cmd == 'bind':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'mgmt_ip_addr',
                                  'mgmt_ip_gw',
                                  'mgmt_bridge',
                                  'ext_iface'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            ext_iface = module.params['ext_iface']
            vlan_base = module.params['vlan_base']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base', 'vlan_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, vlan_base, ext_iface)

            mgmt_ip_addr = module.params['mgmt_ip_addr']
            mgmt_ip_gw = module.params['mgmt_ip_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            net.add_mgmt_port_to_docker(mgmt_bridge, mgmt_ip_addr, mgmt_ip_gw)
            net.up_ext_iface()

            if vms_exists:
                net.add_veth_ports_to_docker()
                net.bind_fp_ports()
                net.bind_vm_backplane()

            if hostif_exists:
                net.inject_host_ports()
        elif cmd == 'unbind':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'ext_iface'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            ext_iface = module.params['ext_iface']
            vlan_base = module.params['vlan_base']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            _, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base', 'vlan_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, vlan_base, ext_iface, False)

            if vms_exists:
                net.unbind_vm_backplane()
                net.unbind_fp_ports()
        elif cmd == 'renumber':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'mgmt_ip_addr',
                                  'mgmt_ip_gw',
                                  'mgmt_bridge',
                                  'ext_iface'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            ext_iface = module.params['ext_iface']
            vlan_base = module.params['vlan_base']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base', 'vlan_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, vlan_base, ext_iface, True)

            mgmt_ip_addr = module.params['mgmt_ip_addr']
            mgmt_ip_gw = module.params['mgmt_ip_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            net.add_mgmt_port_to_docker(mgmt_bridge, mgmt_ip_addr, mgmt_ip_gw)

            if vms_exists:
                new_vlan_base = net.vlan_base
                net.vlan_base = net.find_base_vlan() # Use old vlan base to remove previous vlan
                net.unbind_fp_ports()
                net.vlan_base = new_vlan_base
                # self.vlan_base = restore new one
                net.add_veth_ports_to_docker()
                net.bind_fp_ports()
            if hostif_exists:
                net.inject_host_ports()
        elif cmd == 'connect-vms' or cmd == 'disconnect-vms':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'ext_iface'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            ext_iface = module.params['ext_iface']
            vlan_base = module.params['vlan_base']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base', 'vlan_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, vlan_base, ext_iface)

            if vms_exists:
                if cmd == 'connect-vms':
                    net.bind_fp_ports()
                else:
                    net.bind_fp_ports(True)
        else:
            raise Exception("Got wrong cmd: %s. Ansible bug?" % cmd)

    except Exception as error:
        with open(EXCEPTION_DEBUG_FNAME, 'w') as fp:
            traceback.print_exc(file=fp)
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()

