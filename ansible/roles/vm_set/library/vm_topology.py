#!/usr/bin/python

import subprocess
import re
import os
import os.path
import re
import docker
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
      - connect dut fp ports to bridges representing vm set fp ports
      - connect dut mgmt ports to mgmt bridge (option)
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
    - ptf_mgmt_ip_addr: ip address with prefixlen for the injected docker container
    - ptf_mgmt_ip_gw: default gateway for the injected docker container
    - mgmt_bridge: a bridge which is used as mgmt bridge on the host
    - dut_fp_ports: dut ports
    - dut_mgmt_port: dut mgmt port
    - fp_mtu: MTU for FP ports
'''

EXAMPLES = '''
- name: Create VMs network
  vm_network:
    cmd:          'create'
    vm_names:     "{{ VM_hosts }}"
    fp_mtu:       "{{ fp_mtu_size }}"

- name: Bind topology {{ topo }} to VMs. base vm = {{ VM_base }}
  vm_topology:
    cmd: "bind"
    vm_set_name: "{{ vm_set_name }}"
    topo: "{{ topology }}"
    vm_names: "{{ VM_hosts }}"
    vm_base: "{{ VM_base }}"
    ptf_mgmt_ip_addr: "{{ ptf_ip }}"
    ptf_mgmt_ip_gw: "{{ mgmt_gw }}"
    mgmt_bridge: "{{ mgmt_bridge }}"
    dut_mgmt_port: "{{ dut_mgmt_port }}"
    dut_fp_ports: "{{ dut_fp_ports }}"
    fp_mtu: "{{ fp_mtu_size }}"
    max_fp_num: "{{ max_fp_num }}
'''


DEFAULT_MTU = 0
NUM_FP_VLANS_PER_FP = 4
VM_SET_NAME_MAX_LEN = 8  # used in interface names. So restricted
MGMT_BR_NAME = 'mgmt'
CMD_DEBUG_FNAME = "/tmp/vmtopology.cmds.%s.txt"
EXCEPTION_DEBUG_FNAME = "/tmp/vmtopology.exception.%s.txt"

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

cmd_debug_fname = None

class VMTopology(object):

    def __init__(self, vm_names, fp_mtu, max_fp_num):
        self.vm_names = vm_names
        self.fp_mtu = fp_mtu
        self.max_fp_num = max_fp_num

        self.host_ifaces = VMTopology.ifconfig('ifconfig -a')

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

    def update(self):
        errmsg = []
        i = 0
        while i < 3:
            try:
                self.host_br_to_ifs, self.host_if_to_br = VMTopology.brctl('brctl show')
                self.host_ifaces = VMTopology.ifconfig('ifconfig -a')
                if self.pid is not None:
                    self.cntr_ifaces = VMTopology.ifconfig('nsenter -t %s -n ifconfig -a' % self.pid)
                else:
                    self.cntr_ifaces = []
                break
            except Exception as error:
                errmsg.append(str(error))
                i += 1

        if i == 3:
            raise Exception("update failed for %d times. %s" % (i, "|".join(errmsg)))

        return

    def extract_vm_vlans(self):
        vlans = []
        for attr in self.VMs.itervalues():
            vlans.extend(attr['vlans'])

        return vlans

    def create_bridges(self):
        for vm in self.vm_names:
            for fp_num in xrange(self.max_fp_num):
                fp_br_name = OVS_FP_BRIDGE_TEMPLATE % (vm, fp_num)
                self.create_bridge(fp_br_name, self.fp_mtu)
            bport_br_name = OVS_BRIDGE_BACK_TEMPLATE = 'br-%s-back' % vm
            self.create_bridge(bport_br_name, self.fp_mtu)

        return

    def create_bridge(self, bridge_name, mtu):
        if bridge_name not in self.host_ifaces:
            VMTopology.cmd('ovs-vsctl add-br %s' % bridge_name)

        if mtu != DEFAULT_MTU:
            VMTopology.cmd('ifconfig %s mtu %d' % (bridge_name, mtu))

        VMTopology.cmd('ifconfig %s up' % bridge_name)

        return

    def destroy_bridges(self):
        for vm in self.vm_names:
            for ifname in self.host_ifaces:
                if re.compile(OVS_FP_BRIDGE_REGEX % vm).match(ifname):
                    self.destroy_bridge(ifname)
            bport_br_name = OVS_BRIDGE_BACK_TEMPLATE = 'br-%s-back' % vm
            self.destroy_bridge(bport_br_name)

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
        if int_if in self.host_ifaces and int_if not in self.cntr_ifaces:
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, int_if))

        VMTopology.iface_up(int_if, self.pid)

        return

    def add_ip_to_docker_if(self, int_if, mgmt_ip_addr, mgmt_gw):
        self.update()
        if int_if in self.cntr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip addr flush dev %s" % (self.pid, int_if))
            VMTopology.cmd("nsenter -t %s -n ip addr add %s dev %s" % (self.pid, mgmt_ip_addr, int_if))
            VMTopology.cmd("nsenter -t %s -n ip route add default via %s dev %s" % (self.pid, mgmt_gw, int_if))

        return

    def add_dut_if_to_docker(self, iface_name, dut_iface):

        self.update()
        if dut_iface in self.host_ifaces and dut_iface not in self.cntr_ifaces and iface_name not in self.cntr_ifaces:
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, dut_iface))

        self.update()
        if dut_iface in self.cntr_ifaces and iface_name not in self.cntr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, dut_iface, iface_name))

        VMTopology.iface_up(iface_name, self.pid)

        return

    def remove_dut_if_from_docker(self, iface_name, dut_iface):

        if self.pid is None:
            return

        self.update()
        if iface_name in self.cntr_ifaces:
            VMTopology.iface_down(iface_name, self.pid)

        if iface_name in self.cntr_ifaces and dut_iface not in self.cntr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, iface_name, dut_iface))

        self.update()
        if dut_iface not in self.host_ifaces and dut_iface in self.cntr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip link set netns 1 dev %s" % (self.pid, dut_iface))

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
            elif t_int_if in self.cntr_ifaces:
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, t_int_if, self.fp_mtu))
            elif int_if in self.cntr_ifaces:
                VMTopology.cmd("nsenter -t %s -n ip link set dev %s mtu %d" % (self.pid, int_if, self.fp_mtu))

        VMTopology.iface_up(ext_if)

        self.update()

        if t_int_if in self.host_ifaces and t_int_if not in self.cntr_ifaces and int_if not in self.cntr_ifaces:
            VMTopology.cmd("ip link set netns %s dev %s" % (self.pid, t_int_if))

        self.update()

        if t_int_if in self.cntr_ifaces and int_if not in self.cntr_ifaces:
            VMTopology.cmd("nsenter -t %s -n ip link set dev %s name %s" % (self.pid, t_int_if, int_if))

        VMTopology.iface_up(int_if, self.pid)

        return

    def bind_mgmt_port(self, br_name, mgmt_port):
        if mgmt_port not in self.host_if_to_br:
            VMTopology.cmd("brctl addif %s %s" % (br_name, mgmt_port))

        return

    def unbind_mgmt_port(self, mgmt_port):
        if mgmt_port in self.host_if_to_br:
            VMTopology.cmd("brctl delif %s %s" % (self.host_if_to_br[mgmt_port], mgmt_port))

        return

    def bind_fp_ports(self, disconnect_vm=False):
        for attr in self.VMs.itervalues():
            for vlan_num, vlan in enumerate(attr['vlans']):
               injected_iface = INJECTED_INTERFACES_TEMPLATE % (self.vm_set_name, vlan)
               br_name = OVS_FP_BRIDGE_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               vm_iface = OVS_FP_TAP_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               self.bind_ovs_ports(br_name, self.dut_fp_ports[vlan], injected_iface, vm_iface, disconnect_vm)

        return

    def unbind_fp_ports(self):
        for attr in self.VMs.itervalues():
            for vlan_num, vlan in enumerate(attr['vlans']):
               br_name = OVS_FP_BRIDGE_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               vm_iface = OVS_FP_TAP_TEMPLATE % (self.vm_names[self.vm_base_index + attr['vm_offset']], vlan_num)
               self.unbind_ovs_ports(br_name, vm_iface)

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

            self.unbind_ovs_port(br_name, vm_int_name)

            if back_int_name in self.host_ifaces:
                VMTopology.iface_down(back_int_name)
                VMTopology.cmd("ip link delete dev %s" % back_int_name)

        return

    def bind_ovs_ports(self, br_name, dut_iface, injected_iface, vm_iface, disconnect_vm=False):
        """bind dut/injected/vm ports under an ovs bridge"""
        ports = VMTopology.get_ovs_br_ports(br_name)

        if injected_iface not in ports:
            VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, injected_iface))

        if dut_iface not in ports:
            VMTopology.cmd('ovs-vsctl add-port %s %s' % (br_name, dut_iface))

        bindings = VMTopology.get_ovs_port_bindings(br_name, dut_iface)
        dut_iface_id = bindings[dut_iface]
        injected_iface_id = bindings[injected_iface]
        vm_iface_id = bindings[vm_iface]

        # clear old bindings
        VMTopology.cmd('ovs-ofctl del-flows %s' % br_name)

        if disconnect_vm:
            # Drop packets from VM
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=drop" % (br_name, vm_iface_id))
        else:
            # Add flow from a VM to an external iface
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, vm_iface_id, dut_iface_id))

        if disconnect_vm:
            # Add flow from external iface to ptf container
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, dut_iface_id, injected_iface_id))
        else:
            # Add flow from external iface to a VM and a ptf container
            VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s,%s" % (br_name, dut_iface_id, vm_iface_id, injected_iface_id))

        # Add flow from a ptf container to an external iface
        VMTopology.cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br_name, injected_iface_id, dut_iface_id))

        return

    def unbind_ovs_ports(self, br_name, vm_port):
        """unbind all ports except the vm port from an ovs bridge"""
        ports = VMTopology.get_ovs_br_ports(br_name)

        for port in ports:
            if port != vm_port:
                VMTopology.cmd('ovs-vsctl del-port %s %s' % (br_name, port))

        return

    def unbind_ovs_port(self, br_name, port):
        """unbind a port from an ovs bridge"""
        ports = VMTopology.get_ovs_br_ports(br_name)

        if port in ports:
            VMTopology.cmd('ovs-vsctl del-port %s %s' % (br_name, port))

        return

    def inject_host_ports(self):
        """inject dut port into the ptf docker"""
        self.update()
        for vlan in self.host_interfaces:
            self.add_dut_if_to_docker(PTF_FP_IFACE_TEMPLATE % vlan, self.dut_fp_ports[vlan])

        return

    def deject_host_ports(self):
        """deject dut port from the ptf docker"""
        self.update()
        for vlan in self.host_interfaces:
            self.remove_dut_if_from_docker(PTF_FP_IFACE_TEMPLATE % vlan, self.dut_fp_ports[vlan])

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
        with open(cmd_debug_fname, 'a') as fp:
            pprint("CMD: %s" % cmdline, fp)
        cmd = cmdline.split(' ')
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        ret_code = process.returncode

        if ret_code != 0:
            raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, cmdline))

        with open(cmd_debug_fname, 'a') as fp:
            pprint("OUTPUT: %s" % stdout, fp)
        return stdout

    @staticmethod
    def get_ovs_br_ports(bridge):
        out = VMTopology.cmd('ovs-vsctl list-ports %s' % bridge)
        ports = set()
        for port in out.split('\n'):
            if port != "":
                ports.add(port)
        return ports

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
        cli = docker.from_env()
        try:
            ctn = cli.containers.get(ptf_name)
        except:
            return None

        return ctn.attrs['State']['Pid']

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
            ptf_mgmt_ip_addr=dict(required=False, type='str'),
            ptf_mgmt_ip_gw=dict(required=False, type='str'),
            mgmt_bridge=dict(required=False, type='str'),
            dut_fp_ports=dict(required=False, type='list'),
            dut_mgmt_port=dict(required=False, type='str'),
            fp_mtu=dict(required=False, type='int', default=DEFAULT_MTU),
            max_fp_num=dict(required=False, type='int', default=NUM_FP_VLANS_PER_FP),
        ),
        supports_check_mode=False)

    cmd = module.params['cmd']
    vm_names = module.params['vm_names']
    fp_mtu = module.params['fp_mtu']
    max_fp_num = module.params['max_fp_num']
    dut_mgmt_port = None

    curtime = datetime.datetime.now().isoformat()

    global cmd_debug_fname
    cmd_debug_fname = CMD_DEBUG_FNAME % curtime
    exception_debug_fname = EXCEPTION_DEBUG_FNAME % curtime

    try:
        if os.path.exists(cmd_debug_fname) and os.path.isfile(cmd_debug_fname):
            os.remove(cmd_debug_fname)

        net = VMTopology(vm_names, fp_mtu, max_fp_num)

        if cmd == 'create':
            net.create_bridges()
        elif cmd == 'destroy':
            net.destroy_bridges()
        elif cmd == 'bind':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'ptf_mgmt_ip_addr',
                                  'ptf_mgmt_ip_gw',
                                  'mgmt_bridge',
                                  'dut_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            dut_fp_ports = module.params['dut_fp_ports']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, dut_fp_ports)

            ptf_mgmt_ip_addr = module.params['ptf_mgmt_ip_addr']
            ptf_mgmt_ip_gw = module.params['ptf_mgmt_ip_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            net.add_mgmt_port_to_docker(mgmt_bridge, ptf_mgmt_ip_addr, ptf_mgmt_ip_gw)

            if vms_exists:
                net.add_veth_ports_to_docker()
                if module.params['dut_mgmt_port']:
                    net.bind_mgmt_port(mgmt_bridge, module.params['dut_mgmt_port'])
                net.bind_fp_ports()
                net.bind_vm_backplane()

            if hostif_exists:
                net.inject_host_ports()
        elif cmd == 'unbind':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'dut_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            dut_fp_ports = module.params['dut_fp_ports']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, dut_fp_ports)

            if vms_exists:
                if module.params['dut_mgmt_port']:
                    net.unbind_mgmt_port(module.params['dut_mgmt_port'])
                net.unbind_vm_backplane()
                net.unbind_fp_ports()

            if hostif_exists:
                net.deject_host_ports()
        elif cmd == 'renumber':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'ptf_mgmt_ip_addr',
                                  'ptf_mgmt_ip_gw',
                                  'mgmt_bridge',
                                  'dut_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            dut_fp_ports = module.params['dut_fp_ports']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, dut_fp_ports, True)

            ptf_mgmt_ip_addr = module.params['ptf_mgmt_ip_addr']
            ptf_mgmt_ip_gw = module.params['ptf_mgmt_ip_gw']
            mgmt_bridge = module.params['mgmt_bridge']

            net.add_mgmt_port_to_docker(mgmt_bridge, ptf_mgmt_ip_addr, ptf_mgmt_ip_gw)

            if vms_exists:
                net.unbind_fp_ports()
                net.add_veth_ports_to_docker()
                net.bind_fp_ports()
            if hostif_exists:
                net.inject_host_ports()
        elif cmd == 'connect-vms' or cmd == 'disconnect-vms':
            check_params(module, ['vm_set_name',
                                  'topo',
                                  'dut_fp_ports'], cmd)

            vm_set_name = module.params['vm_set_name']
            topo = module.params['topo']
            dut_fp_ports = module.params['dut_fp_ports']

            if len(vm_set_name) > VM_SET_NAME_MAX_LEN:
                raise Exception("vm_set_name can't be longer than %d characters: %s (%d)" % (VM_SET_NAME_MAX_LEN, vm_set_name, len(vm_set_name)))

            hostif_exists, vms_exists = check_topo(topo)

            if vms_exists:
                check_params(module, ['vm_base'], cmd)
                vm_base = module.params['vm_base']
            else:
                vm_base = None

            net.init(vm_set_name, topo, vm_base, dut_fp_ports)

            if vms_exists:
                if cmd == 'connect-vms':
                    net.bind_fp_ports()
                else:
                    net.bind_fp_ports(True)
        else:
            raise Exception("Got wrong cmd: %s. Ansible bug?" % cmd)

    except Exception as error:
        with open(exception_debug_fname, 'w') as fp:
            traceback.print_exc(file=fp)
        module.fail_json(msg=str(error))

    module.exit_json(changed=True)

if __name__ == "__main__":
    main()

